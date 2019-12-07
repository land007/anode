package com.qhkly.base.cbk;

import org.meshpoint.anode.idl.Callback;

public interface CallbackExample extends Callback {

	public static final String constant1 = "Hello world!";

	public void operation1(String arg1);

	public int getStatus();

	public void setStatus();
	
}
