package com.qhkly.base;

import org.meshpoint.anode.bridge.Env;
import org.meshpoint.anode.idl.IDLInterface;
import org.meshpoint.anode.java.Base;

import com.qhkly.base.cbk.CallbackExample;
import com.qhkly.base.dic.DictExample;

public abstract class PlatformInterfaceExample extends Base {
	private static IDLInterface iface = Env.getCurrent().getInterfaceManager()
			.getByClass(PlatformInterfaceExample.class);

	public PlatformInterfaceExample() {
		super(iface.getId());
	}

	public String attribute1;
	public int attribute2;

	public abstract void operation1(String arg1, DictExample arg2,
			CallbackExample arg3);
}
