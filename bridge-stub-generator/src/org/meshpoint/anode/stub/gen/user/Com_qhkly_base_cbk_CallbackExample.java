/* This file has been automatically generated; do not edit */

package org.meshpoint.anode.stub.gen.user;

public class Com_qhkly_base_cbk_CallbackExample extends org.meshpoint.anode.js.JSInterface implements com.qhkly.base.cbk.CallbackExample {

	private static int classId = org.meshpoint.anode.bridge.Env.getInterfaceId(com.qhkly.base.cbk.CallbackExample.class);

	Com_qhkly_base_cbk_CallbackExample(long instHandle) { super(instHandle); }

	public void finalize() { super.release(classId); }

	private static Object[] __args = new Object[1];

	public int getStatus() {
		return (int)((org.meshpoint.anode.js.JSValue)__invoke(classId, 0, __args)).longValue;
	}

	public void operation1(String arg0) {
		__args[0] = arg0;
		__invoke(classId, 1, __args);
	}

	public void setStatus() {
		__invoke(classId, 2, __args);
	}

	public String get_Constant1() {
		return (String)__get(classId, 0);
	}

	public void set_Constant1(String arg0) {
		__set(classId, 0, arg0);
	}

}
