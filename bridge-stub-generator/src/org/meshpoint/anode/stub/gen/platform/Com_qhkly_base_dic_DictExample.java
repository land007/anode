/* This file has been automatically generated; do not edit */

package org.meshpoint.anode.stub.gen.platform;

public class Com_qhkly_base_dic_DictExample {

	private static Object[] __args = new Object[0];

	public static Object[] __getArgs() { return __args; }

	static Object __get(com.qhkly.base.dic.DictExample inst, int attrIdx) {
		Object result = null;
		switch(attrIdx) {
		case 0: /* constant1 */
			result = com.qhkly.base.dic.DictExample.constant1;
			break;
		case 1: /* member1 */
			result = inst.member1;
			break;
		case 2: /* member2 */
			result = org.meshpoint.anode.js.JSValue.asJSBoolean(inst.member2);
			break;
		default:
		}
		return result;
	}

	static void __set(com.qhkly.base.dic.DictExample inst, int attrIdx, Object val) {
		switch(attrIdx) {
		case 1: /* member1 */
			inst.member1 = (String)val;
			break;
		case 2: /* member2 */
			inst.member2 = ((org.meshpoint.anode.js.JSValue)val).getBooleanValue();
			break;
		default:
			throw new UnsupportedOperationException();
		}
	}

}
