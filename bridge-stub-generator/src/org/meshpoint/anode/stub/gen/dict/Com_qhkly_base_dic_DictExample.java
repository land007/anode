/* This file has been automatically generated; do not edit */

package org.meshpoint.anode.stub.gen.dict;

public class Com_qhkly_base_dic_DictExample {

	private static Object[] __args = new Object[3];

	public static Object[] __getArgs() { return __args; }

	public static void __import(com.qhkly.base.dic.DictExample ob, Object[] vals) {
		ob.member1 = (String)vals[1];
		ob.member2 = ((org.meshpoint.anode.js.JSValue)vals[2]).getBooleanValue();
	}

	public static Object[] __export(com.qhkly.base.dic.DictExample ob) {
		__args[1] = ob.member1;
		__args[2] = org.meshpoint.anode.js.JSValue.asJSBoolean(ob.member2);
		return __args;
	}

}
