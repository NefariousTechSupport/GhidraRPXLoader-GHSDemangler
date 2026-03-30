package cafeloader;

//plagiarized from https://github.com/Maschell/ghs-demangle-java/blob/master/src/main/java/de/mas/wiiu/App.java
//additional code stolen from https://github.com/Cuyler36/Ghidra-GameCube-Loader/blob/master/src/main/java/gamecubeloader/common/CodeWarriorDemangler.java

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.DemanglerParseException;
import ghidra.app.util.demangler.gnu.GhsDemanglerParser;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.util.Map.entry;

public final class GHSDemangler implements Demangler {

	private static List<DemangledParameter> arguments;
	private static DemangledDataType returnType;
	private static boolean isThunk;
	private static boolean varargs;
	private static String mangled;

	private static final String[] templatePrefixes = new String[] { "tm", "ps", "pt" /* XXX from libiberty cplus-dem.c */ };
	private static final Map<String, String> baseNames = Map.ofEntries(
		entry("__vtbl", " virtual table"),
		entry("__ct", "#"),
		entry("__dt", "~#"),
		entry("__as", "operator="),
		entry("__eq", "operator=="),
		entry("__ne", "operator!="),
		entry("__gt", "operator>"),
		entry("__lt", "operator<"),
		entry("__ge", "operator>="),
		entry("__le", "operator<="),
		entry("__pp", "operator++"),
		entry("__pl", "operator+"),
		entry("__apl", "operator+="),
		entry("__mi", "operator-"),
		entry("__ami", "operator-="),
		entry("__ml", "operator*"),
		entry("__amu", "operator*="),
		entry("__dv", "operator/"),
		/* XXX below baseNames have not been seen - guess from libiberty cplus-dem.c */
		entry("__adv", "operator/="),
		entry("__nw", "operator.new"), //TODO: these 4 are modified, the rest is janky
		entry("__dl", "operator.delete"),
		entry("__vn", "operator.new[]"),
		entry("__vd", "operator.delete[]"),
		entry("__md", "operator%"),
		entry("__amd", "operator%="),
		entry("__mm", "operator--"),
		entry("__aa", "operator&&"),
		entry("__oo", "operator||"),
		entry("__or", "operator|"),
		entry("__aor", "operator|="),
		entry("__er", "operator^"),
		entry("__aer", "operator^="),
		entry("__ad", "operator&"),
		entry("__aad", "operator&="),
		entry("__co", "operator~"),
		entry("__cl", "operator()"),
		entry("__ls", "operator<<"),
		entry("__als", "operator<<="),
		entry("__rs", "operator>>"),
		entry("__ars", "operator>>="),
		entry("__rf", "operator->"),
		entry("__vc", "operator[]")
	);
	private final static Map<Character, String> baseTypes = Map.ofEntries(
		entry('v', DemangledDataType.VOID),
		entry('i', DemangledDataType.INT),
		entry('s', DemangledDataType.SHORT),
		entry('c', DemangledDataType.CHAR),
		entry('w', DemangledDataType.WCHAR_T),
		entry('b', DemangledDataType.BOOL),
		entry('f', DemangledDataType.FLOAT),
		entry('d', DemangledDataType.DOUBLE),
		entry('l', DemangledDataType.LONG),
		entry('L', DemangledDataType.LONG_LONG),
		entry('e', DemangledDataType.VARARGS),
		/* XXX below baseTypes have not been seen - guess from libiberty cplus-dem.c */
		entry('r', DemangledDataType.LONG_DOUBLE)
	);
	private final static Map<Character, String> typePrefixes = Map.ofEntries(
		entry('U', DemangledDataType.UNSIGNED),
		entry('S', DemangledDataType.SIGNED),
		/* XXX below typePrefixes have not been seen - guess from libiberty cplus-dem.c */
		entry('J', DemangledDataType.COMPLEX)
	);
	private final static Map<Character, String> typeSuffixes = Map.ofEntries(
		entry('P', DemangledDataType.PTR_NOTATION),
		entry('R', DemangledDataType.REF_NOTATION),
		//entry('C', DemangledDataType.CONST),
		entry('C', ""), //trol
		entry('V', DemangledDataType.VOLATILE), /* XXX this is a guess! */
		/* XXX below typeSuffixes have not been seen - guess from libiberty cplus-dem.c */
		entry('u', DemangledDataType.RESTRICT)
	);

	private static int ReadInt(String name, StringWrapper nameWrapper) {
		if (name == null || name.isEmpty()) {
			throw new IllegalArgumentException("Unexpected end of string. Expected a digit.");
		}
		if (!Character.isDigit(name.charAt(0))) {
			throw new IllegalArgumentException("Unexpected character \"" + name.charAt(0) + "\". Expected a digit.");
		}

		int i = 1;
		while (i < name.length() && Character.isDigit(name.charAt(i))) {
			i++;
		}

		TransparentSWSet(nameWrapper, name.substring(i));

		return Integer.parseInt(name.substring(0, i));
	}

	private static void Decompress() {
		if (!mangled.startsWith("__CPR")) return;
		String name = mangled;

		name = name.substring(5);

		StringWrapper outWrap = new StringWrapper();
		int decompressedLen = ReadInt(name, outWrap);
		name = outWrap.value;

		if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected compressed symbol name.");
		if (!name.startsWith("__"))
			throw new IllegalArgumentException("Unexpected character(s) after compression len: \"" + name.charAt(0) + "\". Expected \"__\".");
		name = name.substring(2);

		String result = "";
		int index = 0;

		/* find all instances of J<num>J */
		while (true) {
			int start = name.indexOf('J', index);

			if (start != -1) {
				result += name.substring(index, index + start - index);

				int end = name.indexOf('J', start + 1);

				if (end != -1) {
					boolean valid = true;

					/* check all characters between Js are digits */
					for (int i = start + 1; i < end; i++)
						if (!Character.isDigit(name.charAt(i))) {
							valid = false;
							break;
						}

					if (end < start) valid = false;

					if (valid) {

						int loc = Integer.parseInt(name.substring(start + 1, start + 1 + end - start - 1));

						String tmp;
						StringWrapper tmpWrap = new StringWrapper();
						int len = ReadInt(result.substring(loc), tmpWrap);
						tmp = tmpWrap.value;

						if (len == 0 || len > tmp.length()) throw new IllegalArgumentException("(DECOMPRESS) Bad string length \"" + len + "\".");

						result += len + tmp.substring(0, len);
						index = end + 1;
					} else {
						result += name.substring(start, start + 1);
						index = start + 1;
					}
				} else {
					result += name.substring(start, start + 1);
					index = start + 1;
				}
			} else {
				result += name.substring(index);
				break;
			}
		}

		if (result.length() != decompressedLen) {
			throw new IllegalArgumentException("Bad decompression length length \"" + decompressedLen + "\". Expected \"" + result.length() + "\".");
		}

		mangled = result;
	}

	private static ArrayList<String> ReadNameSpace(String name) {
		if (name == null || name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"Q\".");
		if (!name.startsWith("Q")) throw new IllegalArgumentException("Unexpected character \"" + name.charAt(0) + "\". Expected \"Q\".");

		StringWrapper outWrap = new StringWrapper();
		int count = ReadInt(name.substring(1), outWrap);
		name = outWrap.value;

		if (count == 0) throw new IllegalArgumentException("Bad namespace count \"" + count + "\".");
		if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
		if (!name.startsWith("_")) throw new IllegalArgumentException("Unexpected character after namespace count \"" + name.charAt(0) + "\". Expected \"_\".");

		mangled = name.substring(1);

		ArrayList<String> result = new ArrayList<String>();
		for (int j = 0; j < count; j++) {
			String current;
			if (mangled.startsWith("Z")) {
				int end = mangled.indexOf("Z", 1);

				if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

				current = mangled.substring(0, end);
				mangled = name.substring(end + 2);
			} else {
				current = ReadString(mangled, null);
			}

			result.add(current);
		}

		return result;
	}

	private static ArrayList<String> ReadNameSpaceSW(String name, StringWrapper remainder) { //TODO: duplicate code, remove alongside SW
		if (name == null || name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"Q\".");
		if (!name.startsWith("Q")) throw new IllegalArgumentException("Unexpected character \"" + name.charAt(0) + "\". Expected \"Q\".");

		StringWrapper outWrap = new StringWrapper();
		int count = ReadInt(name.substring(1), outWrap);
		name = outWrap.value;

		if (count == 0) throw new IllegalArgumentException("Bad namespace count \"" + count + "\".");
		if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
		if (!name.startsWith("_")) throw new IllegalArgumentException("Unexpected character after namespace count \"" + name.charAt(0) + "\". Expected \"_\".");

		remainder.value = name.substring(1);

		ArrayList<String> result = new ArrayList<String>();
		for (int j = 0; j < count; j++) {
			String current;
			if (remainder.value.startsWith("Z")) {
				int end = remainder.value.indexOf("Z", 1);

				if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

				current = remainder.value.substring(0, end);
				remainder.value = name.substring(end + 2);
			} else {
				current = ReadString(remainder.value, remainder);
			}

			result.add(current);
		}

		return result;
	}

	private static String ReadArguments(String name, StringWrapper remainder) {
		StringBuilder result = new StringBuilder();
		List<String> args = new ArrayList<>();

		remainder.value = name;

		while (!remainder.value.isEmpty() && !remainder.value.startsWith("_")) {
			if (!args.isEmpty()) result.append(", ");

			String type = ReadType(args, remainder.value, remainder);
			String typeClean = type.replace("#", "");
			result.append(typeClean);

			/*if(typeClean.equals("char *") || typeClean.equals("char  *")) {
				DemangledDataType hackType = new DemangledDataType(null, null, DemangledDataType.CHAR); //TODO: hack!
				hackType.incrementPointerLevels(); //TODO: i don't know if this is right
				arguments.add(hackType);
			} else if(typeClean.equals("unsigned int")) {
				DemangledDataType hackType = new DemangledDataType(null, null, DemangledDataType.INT);
				hackType.setUnsigned();
				arguments.add(hackType);
			} else if(typeClean.equals(DemangledDataType.VARARGS)) {
				if (arguments.isEmpty()) {
					throw new DemanglerParseException("Demangler outputted varargs before any type was defined!");
				}
				//arguments.get(arguments.size() - 1).setVarArgs();
				varargs = true;
			} else
				arguments.add( new DemangledDataType( null, null, typeClean ) );*/

			args.add(type);
		}

		GhsDemanglerParser parser = new GhsDemanglerParser();
		arguments.addAll(parser.parseParameters(result.toString()));

		return result.toString(); //TODO: this *Might* be redundant
	}

	private static void TransparentSWSet (StringWrapper target, String newValue) {//TODO: temporary helper function, remove alongside SW
		if(target != null)
			target.value = newValue;
		else
			mangled = newValue;
	}

	private static String buildNamespaceString(ArrayList<String> names)
	{
		StringBuilder result = new StringBuilder();

		for (int i = 0; i < names.size(); i++)
		{
			result.append(i > 0 ? "::" : "");
			result.append(names.get(i));
		}

		return result.toString();
	}

	private static String ReadType(List<String> args, String name, StringWrapper remainder) {
		if (name == null || name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected a type.");

		/* e.g. "i" => "int#" */
		if (baseTypes.containsKey(name.charAt(0))) {
			TransparentSWSet(remainder, name.substring(1));
			return baseTypes.get(name.charAt(0)) + "#";
		}
		/* e.g. "Q2_3std4move__tm__2_w" => "std::move<wchar_t>#" */
		else if (name.startsWith("Q")) {
			if(remainder != null)
				return buildNamespaceString(ReadNameSpaceSW(name, remainder)) + "#";
			else
				return buildNamespaceString(ReadNameSpace(name)) + "#";
		}
			/* e.g. "8MyStruct" => "MyStruct#" */
		else if (Character.isDigit(name.charAt(0)))
			return ReadString(name, remainder) + "#";
			/* e.g. "ui" => "unsigned int#" */
		else if (typePrefixes.containsKey(name.charAt(0))) {
			return typePrefixes.get(name.charAt(0)) + ReadType(args, name.substring(1), remainder);
			/* e.g. "Pv" => "void *#" */
		} else if (typeSuffixes.containsKey(name.charAt(0))) {
			return ReadType(args, name.substring(1), remainder).replace("#", " " + typeSuffixes.get(name.charAt(0)) + "#");
			/* e.g. "Z1Z" => "Z1#" */
		} else if (name.startsWith("Z")) {
			int end = name.indexOf("Z", 1);
			if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

			TransparentSWSet(remainder, name.substring(end + 1));
			return name.substring(0, end) + "#";
		}
		/* e.g. "A2_i" => "int#[2]" */
		else if (name.startsWith("A")) {
			String len;

			name = name.substring(1);

			if (name.startsWith("_Z")) {
				int end = name.indexOf("Z", 2);

				if (end == -1) throw new IllegalArgumentException("Unexpected end of string. Expected \"Z\".");

				len = name.substring(1, 1 + end - 1);
				name = name.substring(end + 1);
			} else {
				StringWrapper nameWrapper = new StringWrapper();
				len = Integer.toString(ReadInt(name, nameWrapper));
				name = nameWrapper.value;
			}

			if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!name.startsWith("_"))
				throw new IllegalArgumentException("Unexpected character after array length \"" + name.charAt(0) + "\". Expected \"_\".");

			return ReadType(args, name.substring(1), remainder).replace("#", "#[" + len + "]");
		}
		/* e.g. "FPv_v" => "void (#)(void *)" */
		else if (name.startsWith("F")) {
			StringWrapper nameWrapper = new StringWrapper();
			String declArgs = ReadArguments(name.substring(1), nameWrapper);
			name = nameWrapper.value;

			/* XXX bit of a hack - we're allowed not to have a return type on top level methods, which we detected by the args argument being null. */

			boolean parseable = false;
			try {
				if (!name.isEmpty()) {
					Integer.parseInt(name.substring(1));
					parseable = true;
				}
			} catch (NumberFormatException ignored) {}
			if (args == null) {
				if (name.isEmpty() || (name.startsWith("_") && parseable)) {
					TransparentSWSet(remainder, name);
					return "#(" + declArgs + ")";
				}

			}

			if (name.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!name.startsWith("_"))
				throw new IllegalArgumentException("Unexpected character after argument declaration \"" + name.charAt(0) + "\". Expected \"_\".");

			return ReadType(args, name.substring(1), remainder).replace("#", "(#)(" + declArgs + ")");
		}
		/* T<a> expands to argument <a> */
		else if (name.startsWith("T")) {
			if (name.length() < 2) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!Character.isDigit(name.charAt(1))) throw new IllegalArgumentException("Unexpected character \"" + name.charAt(1) + "\". Expected a digit.");

			int arg = Integer.parseInt(name.substring(1, 2));

			TransparentSWSet(remainder, name.substring(2));

			if (args.size() < arg) throw new IllegalArgumentException("Bad argument number \"" + arg + "\".");

			return args.get(arg - 1);
		}
		/* N<c><a> expands to <c> repetitions of argument <a> */
		else if (name.startsWith("N")) {
			if (name.length() < 3) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
			if (!Character.isDigit(name.charAt(1)) || !Character.isDigit(name.charAt(2)))
				throw new IllegalArgumentException("Unexpected character(s) \"" + name.charAt(1) + name.charAt(2) + "\". Expected two digits.");

			int count = Integer.parseInt(name.substring(1, 2));
			int arg = Integer.parseInt(name.substring(2, 3));

			if (count > 1)
				TransparentSWSet(remainder, "N" + (count - 1) + arg + name.substring(3));
			else
				TransparentSWSet(remainder, name.substring(3));

			if (args.size() < arg) throw new IllegalArgumentException("Bad argument number \"" + arg + "\".");

			return args.get(arg - 1);
		} else
			throw new IllegalArgumentException("Unknown type: \"" + name.charAt(0) + "\".");
	}

	private static String ReadString(String name, StringWrapper remainder) {
		if(name == null)
			name = mangled;

		if (name.isEmpty())
			throw new IllegalArgumentException("Unexpected end of string. Expected a digit.");

		StringWrapper nameWrapper = new StringWrapper();
		int len = ReadInt(name, nameWrapper);
		name = nameWrapper.value;
		if (len == 0 || name.length() < len) throw new IllegalArgumentException("(READ STRING) Bad string length \"" + len + "\".");
		TransparentSWSet(remainder, name.substring(len));
		return DemangleTemplate(name.substring(0, len));
	}

	private static String ReadTemplateArguments(String name, StringWrapper remainder) {
		StringBuilder result = new StringBuilder();
		List<String> args = new ArrayList<>();

		remainder.value = name;

		while (!remainder.value.isEmpty() && !remainder.value.startsWith("_")) {
			if (!args.isEmpty()) result.append(", ");

			String type, val;

			if (remainder.value.startsWith("X")) {
				/* X arguments represent named values */

				remainder.value = remainder.value.substring(1);
				if (remainder.value.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected a type.");

				if (Character.isDigit(remainder.value.charAt(0))) {
					/* arbitrary string */
					type = "#";

					val = ReadString(remainder.value, remainder);
				} else {
					/* <type><encoding> */
					type = ReadType(args, remainder.value, remainder).replace("#", " #");

					if (remainder.value.startsWith("L")) {
						/* _<len>_<val> */
						remainder.value = remainder.value.substring(1);
						if (remainder.value.isEmpty()) throw new IllegalArgumentException("Unexpected end of string. Expected \"_\".");
						if (!remainder.value.startsWith("_")) throw new IllegalArgumentException(
								"Unexpected character after template parameter encoding \"" + remainder.value.charAt(0) + "\". Expected \"_\".");

						int len = ReadInt(remainder.value.substring(1), remainder);

						if (len == 0 || len > remainder.value.length() + 1)
							throw new IllegalArgumentException("Bad template parameter length: \"" + len + "\".");
						if (!remainder.value.startsWith("_")) throw new IllegalArgumentException(
								"Unexpected character after template parameter length \"" + remainder.value.charAt(0) + "\". Expected \"_\".");

						remainder.value = remainder.value.substring(1);
						val = remainder.value.substring(0, len);
						remainder.value = remainder.value.substring(len);
					} else
						throw new IllegalArgumentException("Unknown template parameter encoding: \"" + remainder.value.charAt(0) + "\".");
				}
			} else {
				val = ReadType(args, remainder.value, remainder).replace("#", "");
				type = "class #";
			}

			/* TODO - the Z notation is ugly - we should resolve args? */
			result.append(type.replace("#", "Z" + (args.size() + 1) + " = " + val));
			args.add(val);
		}

		return result.toString();
	}

	static boolean HasTemplatePrefixes(String str) {
		for (String s : templatePrefixes)
			if (str.startsWith(s)) return true;
		return false;
	}

	private static String DemangleTemplate(String name) {
		int mstart;

		mstart = name.indexOf("__", 1);

		/* check for something like "h___tm_2_i" => "h_<int>" */
		if (mstart != -1 && name.substring(mstart).startsWith("___")) mstart++;

		/* not a special symbol name! */
		if (mstart == -1) return name;

		/* something more interesting! */
		String remainder = name.substring(mstart + 2);
		name = name.substring(0, mstart);

		StringBuilder nameBuilder = new StringBuilder(name);
		while (true) {
			if (!HasTemplatePrefixes(remainder)) {
				// throw new IllegalArgumentException("Unexpected template argument prefix. " + remainder);
				return name;
			}

			/* format of remainder should be <type>__<len>_<arg> */
			int lstart = remainder.indexOf("__");

			if (lstart == -1) throw new IllegalArgumentException("Bad template argument: \"" + remainder + "\".");

			remainder = remainder.substring(lstart + 2);

			StringWrapper wrapOut = new StringWrapper();

			int len = ReadInt(remainder, wrapOut);
			remainder = wrapOut.value;

			if (len == 0 || len > remainder.length()) throw new IllegalArgumentException("Bad template argument length: \"" + len + "\".");
			if (!remainder.startsWith("_"))
				throw new IllegalArgumentException("Unexpected character after template argument length \"" + remainder.charAt(0) + "\". Expected \"_\".");

			String tmp;
			StringWrapper tmpWrap = new StringWrapper();
			String declArgs = ReadTemplateArguments(remainder.substring(1), tmpWrap);
			tmp = tmpWrap.value;

			/* avoid emitting the ">>" token */
			if (declArgs.endsWith(">")) declArgs += " ";

			nameBuilder.append("<");
			nameBuilder.append(declArgs);
			nameBuilder.append(">");

			remainder = remainder.substring(len);

			if (!tmp.contentEquals(remainder)) throw new IllegalArgumentException("Bad template argument length: \"" + len + "\".");

			/* check if we've hit the end */
			if (remainder.isEmpty()) return nameBuilder.toString();

			/* should be immediately followed with __ */
			if (!remainder.startsWith("__"))
				throw new IllegalArgumentException("Unexpected character(s) after template: \"" + remainder.charAt(0) + "\". Expected \"__\".");
			remainder = remainder.substring(2);
		}
	}

	private static String ReadBaseName() {
		String opName;
		String name = mangled;
		int mstart;

		if (name == null || name.isEmpty()) { //TODO: this *should* never be able to happen
			throw new IllegalArgumentException("Unexpected end of string. Expected a name.");
		}

		if (name.startsWith("__op")) {
			StringWrapper stringOut = new StringWrapper();
			/* a cast operator */
			String type = ReadType(null, name.substring(4), stringOut).replace("#", "");
			name = stringOut.value;
			opName = "operator " + type;
			name = "#" + name;
		} else {
			opName = "";
		}

		mstart = name.indexOf("__", 1);

		/* check for something like "h___Fi" => "h_" */
		if (mstart != -1 && name.substring(mstart).startsWith("___")) mstart++;

		/* not a special symbol name! */
		if (mstart == -1) {
			mangled = "";
			return name;
		}

		/* something more interesting! */
		mangled = name.substring(mstart + 2);
		name = name.substring(0, mstart);

		/* check for "__ct__7MyClass" */
		if (baseNames.containsKey(name))
			name = baseNames.get(name);
		else if (name.equals("#")) name = opName;

		StringBuilder nameBuilder = new StringBuilder(name);
		while (HasTemplatePrefixes(mangled)) {
			/* format of remainder should be <type>__<len>_<arg> */
			int lstart = mangled.indexOf("__");

			if (lstart == -1) throw new IllegalArgumentException("Bad template argument: \"" + mangled + "\".");

			/* shift across the template type */
			nameBuilder.append("__");
			nameBuilder.append(mangled, 0, lstart);

			mangled = mangled.substring(lstart + 2);

			int len = ReadInt(mangled, null);

			if (len == 0 || len > mangled.length()) throw new IllegalArgumentException("Bad template argument length: \"" + len + "\".");

			/* shift across the len and arg */
			nameBuilder.append("__");
			nameBuilder.append(len);
			nameBuilder.append(mangled, 0, len);

			mangled = mangled.substring(len);

			/* check if we've hit the end */
			if (mangled.isEmpty()) return nameBuilder.toString();

			/* should be immediately followed with __ */
			if (!mangled.startsWith("__"))
				throw new IllegalArgumentException("Unexpected character(s) after template: \"" + mangled.charAt(0) + "\". Expected \"__\".");
			mangled = mangled.substring(2);
		}

		return DemangleTemplate(nameBuilder.toString());
	}

	public GHSDemangler() {
		// needed to instantiate dynamically
	}

	@Override  //TODO: the demangler outputs types like "char const *" or "unsigned int" instead of just "char *" or "uint" so ghidra doesn't work properly with that
	public DemangledObject demangle(MangledContext context) { //TODO: get rid of StringWrapper
		String symbol = context.getMangled();
		DemanglerOptions options = context.getOptions();
		char lastChar = symbol.charAt(symbol.length() - 1);
		while (lastChar == ' ') {
			lastChar = symbol.charAt(symbol.length() - 1);
			symbol = symbol.substring(0, symbol.length() - 1);
		}

		mangled = symbol;
		returnType = null;
		arguments = new ArrayList<>();
		isThunk = false;
		varargs = false;
		int trailingNumber = -512;

		if (mangled.startsWith("__sti__")) {
			throw new DemanglerParseException("\"__sti__\" pattern is unsupported.");
		}

		if( !options.demangleOnlyKnownPatterns() && mangled.matches("___CPR.*_[0-9]")) {
			Msg.info(GHSDemangler.class, "linker duplicate?");
			trailingNumber = mangled.charAt(mangled.length() - 1) - '0'; //the zero is here for char -> int
			mangled = mangled.substring(0, mangled.length() - 2);
		}

		if ( !options.demangleOnlyKnownPatterns() && mangled.matches("^__ghs_thunk__0x[a-f 0-9]{8}__.*") ) { //regex here matches the memory address, if you are wondering
			mangled = mangled.substring(25);
			isThunk = true;
		}
		Decompress();
		if(trailingNumber != -512) //bogus value that we can detect
			mangled = mangled + '_' + trailingNumber;

		/*
		 * This demangle method has basically turned into a hand-written LL(1) recursive descent parser.
		 */

		String baseName = ReadBaseName();

		/* TODO this may not be right - see S below Q */
		/* h__S__Q1_3clsFi => static cls::h(int) */
		boolean isStatic = false;

		if (mangled.startsWith("S__")) {
			isStatic = true;
			mangled = mangled.substring(3);
		}
		ArrayList<String> declNameSpace = new ArrayList<String>();
		String declClass = "";

		if (mangled.startsWith("Q")) {
			declNameSpace = ReadNameSpace(mangled);

			if (declNameSpace.size() > 0)
			{
				declClass = declNameSpace.get(declNameSpace.size() - 1);
			}

		} else if (!mangled.isEmpty() && Character.isDigit(mangled.charAt(0))) {
			declClass = ReadString(null, null);
			declNameSpace.add(declClass);
		} else {
			// Nothing
		}

		baseName = baseName.replace("#", declClass);//TODO: what?

		/* static */
		if (mangled.startsWith("S")) {
			isStatic = true;
			mangled = mangled.substring(1);
		}

		//boolean isConst = false;
		if (mangled.startsWith("C")) {
			//isConst = true;
			mangled = mangled.substring(1);
		}

		arguments = new ArrayList<>();
		String declType;
		if (mangled.startsWith("F"))
			declType = ReadType(null, mangled, null); //TODO: we don't need to pass mangled
		else
			declType = "#";

		int returnIndex = declType.indexOf("(#)("); //TODO: bad no good bad bad hack
		if( returnIndex != -1 )
			returnType = new DemangledDataType(null, null, declType.substring(0, returnIndex));

		/* XXX bit of a hack - some names I see seem to end with _<number> */
		int end;
		if (mangled.startsWith("_")) {
			end = Integer.parseInt(mangled.substring(1));

			baseName += "_" + end;
			mangled = "";
		}

		if (!mangled.isEmpty())
			throw new IllegalArgumentException("Unknown modifier: \"" + mangled.charAt(0) + "\".");

		//String result = ((isStatic ? "static " : "") + declType.replace("(#)", " " + declNameSpace + baseName).replace("#", declNameSpace + baseName) + (isConst ? " const" : "") )
		//		.replace("::" + baseNames.get("__vtbl"), baseNames.get("__vtbl")); //TODO: no

		DemangledFunction demangled = new DemangledFunction(symbol, symbol, baseName); //TODO: formerly result was the second arg but that's gone now since i broke it

		if(!declNameSpace.isEmpty())
		{
			GhsDemanglerParser parser = new GhsDemanglerParser();
			demangled.setNamespace(parser.convertToNamespaces(declNameSpace));
		}

		demangled.setStatic(isStatic);

		if(options.applyCallingConvention())
			demangled.setCallingConvention( !declClass.isEmpty() ? "__thiscall" : "__stdcall" ); //TODO: what does this mean
		//TODO: surely there is some DemangledFunction.THISCALL constant from ghidra that we can use here

		if(options.applySignature()) {
			for (DemangledParameter param : arguments) //lol, lmao
				demangled.addParameter(param);

			if(varargs) {
				DemangledDataType variadic = new DemangledDataType(null, null, DemangledDataType.VARARGS);
				variadic.setVarArgs();
				demangled.addParameter(new DemangledParameter(variadic));
			}

			if(returnType != null)
				demangled.setReturnType(returnType);
		}

		if(returnType != null && returnType.getName().matches("Z[0-9]*")) {
			Msg.error(GHSDemangler.class, "template/1 " + symbol + " (" + declType + ')' + '(' + returnType.getName() + ')');
			throw new DemanglerParseException("/!\\ Broken Templates detected/1");
		}

		if(declType.matches(".*Z[0-9]* = Z[0-9]*.*")) {
			Msg.error(GHSDemangler.class, "template/2 " + symbol + " (" + declType + ')');
			throw new DemanglerParseException("/!\\ Broken Templates detected/2");
		}

		demangled.setThunk(isThunk);
		return demangled;
	}

	@Override
	public boolean canDemangle(Program program) {
		return (program.getLanguageID().getIdAsString().equals("PowerPC:BE:32:Gekko_Broadway_Espresso"));
	}

	@Override
	public DemanglerOptions createDefaultOptions() {
		return Demangler.super.createDefaultOptions();
	}
}