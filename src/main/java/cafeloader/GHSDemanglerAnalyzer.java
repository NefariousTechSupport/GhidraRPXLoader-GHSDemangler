package cafeloader;

import ghidra.app.plugin.core.analysis.AbstractDemanglerAnalyzer;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.MangledContext;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

//based off of https://github.com/Cuyler36/Ghidra-GameCube-Loader/blob/master/src/main/java/gamecubeloader/common/CodeWarriorDemangler.java
//and https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/MicrosoftDemangler/src/main/java/ghidra/app/plugin/core/analysis/MicrosoftDemanglerAnalyzer.java

public class GHSDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangle GHS";
	private static final String DESCRIPTION =
			"After a function is created, this analyzer will attempt to demangle " +
					"the name and apply datatypes to parameters." +
					"WARNING: this demangler is entirely based on guesswork, as GHS obviously isn't planning on releasing their documentation any time soon";
	private static final String OPTION_NAME_APPLY_SIGNATURE = "apply function signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
			"apply decoded function signature alongside basename and class ";

	private static final String OPTION_NAME_APPLY_ONLY_KNOWN = "apply only known symbol patterns";
	private static final String OPTION_DESCRIPTION_APPLY_ONLY_KNOWN = "only apply known symbols patterns and exclude any based on guesswork";

	private static final String OPTION_NAME_APPLY_CALLING_CONVENTION = "apply calling convention";
	private static final String OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION = "apply calling convention to functions";

	//private static final String OPTION_NAME_WRITE_LOGS = "write logs";
	//private static final String OPTION_DESCRIPTION_WRITE_LOGS = "write debug logs into the ghidra user log";

	private boolean applyFunctionSignature = true;
	private boolean applyOnlyKnown = false;
	private boolean applyCallingConvention = false;
	//private boolean writeLogs = false;

	public GHSDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		demangler = new GHSDemangler();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature, null, OPTION_DESCRIPTION_APPLY_SIGNATURE);
		options.registerOption(OPTION_NAME_APPLY_ONLY_KNOWN, applyOnlyKnown, null, OPTION_DESCRIPTION_APPLY_ONLY_KNOWN);
		options.registerOption(OPTION_NAME_APPLY_CALLING_CONVENTION, applyCallingConvention, null, OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION);
		//options.registerOption(OPTION_NAME_WRITE_LOGS, writeLogs, null, OPTION_DESCRIPTION_WRITE_LOGS);
	}


	@Override
	public void optionsChanged(Options options, Program program) {
		applyFunctionSignature = options.getBoolean(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature);
		applyOnlyKnown = options.getBoolean(OPTION_NAME_APPLY_ONLY_KNOWN, applyOnlyKnown);
		applyCallingConvention = options.getBoolean(OPTION_NAME_APPLY_CALLING_CONVENTION, applyCallingConvention);
		//writeLogs = options.getBoolean(OPTION_NAME_WRITE_LOGS, writeLogs);
	}


	@Override
	protected DemangledObject doDemangle(MangledContext context, MessageLog log)
			throws DemangledException {
		context.getOptions().setApplySignature(applyFunctionSignature);
		context.getOptions().setDemangleOnlyKnownPatterns(applyOnlyKnown);
		context.getOptions().setApplyCallingConvention(applyCallingConvention);
		//demangler.writeLogs = true;
		return demangler.demangle(context);
	}

}
