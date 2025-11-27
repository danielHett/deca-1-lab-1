package analysis.exercise2;

import analysis.FileStateFact;
import analysis.ForwardAnalysis;
import analysis.VulnerabilityReporter;

import java.util.HashSet;
import java.util.Set;

import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.expr.JVirtualInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.JReturnVoidStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.JavaSootMethod;

import javax.annotation.Nonnull;

public class TypeStateAnalysis extends ForwardAnalysis<Set<FileStateFact>> {

	public TypeStateAnalysis(@Nonnull JavaSootMethod method, @Nonnull VulnerabilityReporter reporter) {
		super(method, reporter);
	}

	@Override
	protected void flowThrough(@Nonnull Set<FileStateFact> in, @Nonnull Stmt stmt, @Nonnull Set<FileStateFact> out) {
		copy(in, out);
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
					for (FileStateFact fsf : out) {
						if (fsf.containsAlias(rightOp)) {
							rFile = fsf;
						}
					}

					if (rFile != null) {
						rFile.addAlias(leftOp);
					}
				}
			}
		}

		// If it's not an assignment, we are looking for open/close statements.
		if (stmt instanceof JInvokeStmt && ((JInvokeStmt) stmt).getInvokeExpr() instanceof JVirtualInvokeExpr) {
			JVirtualInvokeExpr invokeExpr = (JVirtualInvokeExpr) ((JInvokeStmt) stmt).getInvokeExpr();
			String callingAlias = invokeExpr.getBase().toString();
			String className = invokeExpr.getMethodSignature().getDeclClassType().toString();
			String mathodName = invokeExpr.getMethodSignature().getName();

			// First, is the base an alias we've already seen?
			FileStateFact targetFsf = null;
			for (FileStateFact fsf : out) {
				if (fsf.containsAlias(callingAlias)) {
					targetFsf = fsf;
				}
			}

			if (targetFsf != null && className.equals("target.exercise2.File") && mathodName.equals("open")) {
				targetFsf.updateState(FileStateFact.FileState.Open);
			}

			if (targetFsf != null && className.equals("target.exercise2.File") && mathodName.equals("close")) {
				targetFsf.updateState(FileStateFact.FileState.Close);
			}
		}

		if (stmt instanceof JReturnVoidStmt || stmt instanceof JReturnStmt) {
			for (FileStateFact fsf : out) {
				if (fsf.getState() == FileStateFact.FileState.Open) {
					MethodSignature currentMethodSig = method.getSignature();
					this.reporter.reportVulnerability(currentMethodSig, stmt);
				}
			}
		}
	}

	@Nonnull
	@Override
	protected Set<FileStateFact> newInitialFlow() {
		return new HashSet<>();
	}

	@Override
	protected void copy(@Nonnull Set<FileStateFact> source, @Nonnull Set<FileStateFact> dest) {
		for (FileStateFact fsf : source) {
			dest.add(new FileStateFact(fsf));
		}
	}

	@Override
	protected void merge(@Nonnull Set<FileStateFact> in1, @Nonnull Set<FileStateFact> in2,
			@Nonnull Set<FileStateFact> out) {
		// Simple lattice:
		// Close
		// |
		// Open
		// |
		// Init

		// First, let's find all pairs from the two sets of states.

		for (FileStateFact x : in1) {
			// We store the matching state of x in m.
			FileStateFact m = null;
			for (FileStateFact y : in2) {
				// If we found a match, set m to the matching state and break.
				if (y.equals(x)) {
					m = y;
					break;
				}
			}

			if (m != null) {
				FileStateFact newFsf = new FileStateFact(m);
				newFsf.updateState(mergeStates(x.getState(), m.getState()));
				out.add(new FileStateFact(newFsf));
			} else {
				out.add(new FileStateFact(x));
			}

		}
	}

	private FileStateFact.FileState mergeStates(FileStateFact.FileState x, FileStateFact.FileState y) {
		return stateToInt(x) > stateToInt(y) ? x : y;
	}

	private int stateToInt(FileStateFact.FileState x) {
		if (x == FileStateFact.FileState.Init)
			return 0;
		else if (x == FileStateFact.FileState.Open)
			return 1;
		else
			return 3;
	}
}
