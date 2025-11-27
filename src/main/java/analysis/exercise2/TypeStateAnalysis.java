package analysis.exercise2;

import analysis.FileStateFact;
import analysis.ForwardAnalysis;
import analysis.VulnerabilityReporter;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import sootup.core.jimple.basic.LValue;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;
import sootup.core.jimple.common.expr.JVirtualInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.JReturnVoidStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootMethod;

import javax.annotation.Nonnull;

public class TypeStateAnalysis extends ForwardAnalysis<Set<FileStateFact>> {

	public TypeStateAnalysis(@Nonnull JavaSootMethod method, @Nonnull VulnerabilityReporter reporter) {
		super(method, reporter);
		// System.out.println(method.getBody());
	}

	@Override
	protected void flowThrough(@Nonnull Set<FileStateFact> in, @Nonnull Stmt stmt, @Nonnull Set<FileStateFact> out) {
		copy(in, out);
		// TODO: Implement your flow function here.
		// MethodSignature currentMethodSig = method.getSignature();
		// this.reporter.reportVulnerability(currentMethodSig, stmt);

		// If it's an assignment, we need to check if a file object is getting a new
		// alias.
		if (stmt instanceof JAssignStmt) {
			// First check if the left/right side are file types.
			Value leftOp = ((JAssignStmt) stmt).getLeftOp();
			Value rightOp = ((JAssignStmt) stmt).getRightOp();

			if (leftOp.getType().toString().equals("target.exercise2.File")
					&& rightOp.getType().toString().equals("target.exercise2.File")) {
				// Then, check if we are creating a new file. If we are, then we need a new
				// FileState
				if (rightOp.toString().equals("new target.exercise2.File")) {
					// Create the new state and add the alias.
					FileStateFact newState = new FileStateFact(FileStateFact.FileState.Init);
					newState.addAlias(leftOp);
					// Add it to the output set.
					out.add(newState);
					// We are assigning an existing file to an alias.
				} else {
					// First find the alias in the in set.
					FileStateFact rFile = null;
					for (FileStateFact fsf : in) {
						if (fsf.containsAlias(rightOp)) {
							rFile = fsf;
						}
					}

					if (rFile != null) {
						rFile.addAlias(leftOp);
					}
				}
			}

			// System.out.println("The leftOp: " + leftOp);
			// System.out.println("The rightOp: " + ((JAssignStmt)
			// stmt).getRightOp().getType().toString());
		}

		// If it's not an assignment, we are looking for open/close statements.
		if (stmt instanceof JInvokeStmt && ((JInvokeStmt) stmt).getInvokeExpr() instanceof JVirtualInvokeExpr) {
			JVirtualInvokeExpr invokeExpr = (JVirtualInvokeExpr) ((JInvokeStmt) stmt).getInvokeExpr();
			String callingAlias = invokeExpr.getBase().toString();
			String className = invokeExpr.getMethodSignature().getDeclClassType().toString();
			String mathodName = invokeExpr.getMethodSignature().getName();

			// First, is the base an alias we've already seen?
			FileStateFact targetFsf = null;
			for (FileStateFact fsf : in) {
				if (fsf.containsAlias(callingAlias)) {
					targetFsf = fsf;
				}
			}

			// TODO: What should happen if you try to open an open file?
			if (targetFsf != null && className.equals("target.exercise2.File") && mathodName.equals("open")) {
				targetFsf.updateState(FileStateFact.FileState.Open);
			}

			// TODO: What should happen if you try to close a closed file?
			if (targetFsf != null && className.equals("target.exercise2.File") && mathodName.equals("close")) {
				targetFsf.updateState(FileStateFact.FileState.Close);
			}
		}
		prettyPrint(in, stmt, out);
	}

	@Nonnull
	@Override
	protected Set<FileStateFact> newInitialFlow() {
		return new HashSet<>();
	}

	@Override
	protected void copy(@Nonnull Set<FileStateFact> source, @Nonnull Set<FileStateFact> dest) {
		System.out.println("The destination is empty:  " + (dest.isEmpty() ? "Yes!" : "No!"));
		for (FileStateFact fsf : source) {
			dest.add(fsf);
		}
	}

	@Override
	protected void merge(@Nonnull Set<FileStateFact> in1, @Nonnull Set<FileStateFact> in2,
			@Nonnull Set<FileStateFact> out) {
		// TODO: Implement the merge function here.
	}

}
