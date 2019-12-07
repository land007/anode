package com.qhkly.base.impl;

import org.meshpoint.anode.module.IModule;
import org.meshpoint.anode.module.IModuleContext;

import com.qhkly.base.PlatformInterfaceExample;
import com.qhkly.base.cbk.CallbackExample;
import com.qhkly.base.dic.DictExample;

public class PlatformImplExample extends PlatformInterfaceExample implements
		IModule {
	public PlatformImplExample() {
		super();
		attribute1 = "a default value";
		attribute2 = 42;
	}

	public void operation1(String arg1, DictExample arg2, CallbackExample arg3) {
		arg3.operation1(arg2.member1 + arg1);
	}

	public Object startModule(IModuleContext ctx) {
		return this;
	}

	public void stopModule() {
	}
}
