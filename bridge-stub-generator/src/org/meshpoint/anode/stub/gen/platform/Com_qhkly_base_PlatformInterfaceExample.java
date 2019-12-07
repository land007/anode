/* This file has been automatically generated; do not edit */

package org.meshpoint.anode.stub.gen.platform;

public class Com_qhkly_base_PlatformInterfaceExample {

	private static Object[] __args = new Object[3];

	public static Object[] __getArgs() { return __args; }

	static Object __invoke(com.qhkly.base.PlatformInterfaceExample inst, int opIdx, Object[] args) {
		inst.operation1(
			(String)args[0],
			(com.qhkly.base.dic.DictExample)args[1],
			(com.qhkly.base.cbk.CallbackExample)args[2]
		);
		return null;
	}

	static Object __get(com.qhkly.base.PlatformInterfaceExample inst, int attrIdx) {
		Object result = null;
		switch(attrIdx) {
		case 0: /* attribute1 */
			result = inst.attribute1;
			break;
		case 1: /* attribute2 */
			result = org.meshpoint.anode.js.JSValue.asJSNumber((long)inst.attribute2);
			break;
		default:
		}
		return result;
	}

	static void __set(com.qhkly.base.PlatformInterfaceExample inst, int attrIdx, Object val) {
		switch(attrIdx) {
		case 0: /* attribute1 */
			inst.attribute1 = (String)val;
			break;
		case 1: /* attribute2 */
			inst.attribute2 = (int)((org.meshpoint.anode.js.JSValue)val).longValue;
			break;
		default:
			throw new UnsupportedOperationException();
		}
	}

}
