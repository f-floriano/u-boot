/**
 * @name Network byte swap to memcpy
 * @description Insecure memcpy size parameter controlled by network data
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id cpp/uboot-network-memcpy-taint
 * @tags security
 *       external/cwe/cwe-120
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName() in ["ntohs", "ntohl", "ntohll"] and
      this = mi.getExpr()
    )
  }
}

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      call.getTarget().getName() = "memcpy" and
      sink.asExpr() = call.getArgument(2)
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
