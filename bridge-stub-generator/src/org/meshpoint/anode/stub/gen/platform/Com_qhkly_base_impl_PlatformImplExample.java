/* This file has been automatically generated; do not edit */

package org.meshpoint.anode.stub.gen.platform;

public class Com_qhkly_base_impl_PlatformImplExample {

	private static Object[] __args = new Object[3];

	public static Object[] __getArgs() { return __args; }

	static Object __invoke(com.qhkly.base.impl.PlatformImplExample inst, int opIdx, Object[] args) {
		Object result = null;
		switch(opIdx) {
		case 0: /* operation1 */
			inst.operation1(
				(String)args[0],
				(com.qhkly.base.dic.DictExample)args[1],
				(com.qhkly.base.cbk.CallbackExample)args[2]
			);
			break;
		case 1: /* stopModule */
			inst.stopModule();
			break;
		default:
		}
		return result;
	}

}
