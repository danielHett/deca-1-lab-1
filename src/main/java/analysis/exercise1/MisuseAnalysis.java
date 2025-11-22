package analysis.exercise1;

import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;

import java.util.List;

import javax.annotation.Nonnull;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.Type;
import sootup.java.core.JavaSootMethod;

public class MisuseAnalysis extends AbstractAnalysis {
	public MisuseAnalysis(@Nonnull JavaSootMethod method, @Nonnull VulnerabilityReporter reporter) {
		super(method, reporter);
	}

	@Override
	protected void flowThrough(@Nonnull Stmt stmt) {

		// Two possibilities:
		// (1) we have an invoke statement.
		// (2) we have an assign statement with an invocation on the righthand side.
		AbstractInvokeExpr invocationExpression = stmt instanceof JInvokeStmt ? ((JInvokeStmt) stmt).getInvokeExpr()
				: null;
		invocationExpression = (stmt instanceof JAssignStmt)
				&& (((JAssignStmt) stmt).getRightOp() instanceof AbstractInvokeExpr)
						? (AbstractInvokeExpr) ((JAssignStmt) stmt).getRightOp()
						: invocationExpression;

		// Do we have an bad invocation?
		if (invocationExpression != null && isTargetMethod(invocationExpression)
				&& !invocationExpression.getArg(0).toString().equals("\"AES/GCM/PKCS5Padding\"")) {
			reporter.reportVulnerability(method.getSignature(), stmt);
		}
	}

	private boolean isTargetMethod(AbstractInvokeExpr invocationExpression) {
		// First pull out the signature.
		MethodSignature signature = invocationExpression.getMethodSignature();

		// We get the necessary details.
		String declClassType = signature.getDeclClassType().toString();
		String methodName = signature.getName();
		int numMethodArgs = signature.getParameterTypes().size();
		List<Type> methodArgTypes = signature.getParameterTypes();

		return methodName.equals("getInstance") && declClassType.equals("javax.crypto.Cipher") && numMethodArgs == 1
				&& (methodArgTypes.get(0).toString().equals("java.lang.String"));
	}
}
