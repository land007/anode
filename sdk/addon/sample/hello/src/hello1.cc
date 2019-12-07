// addons/hello/hello.cc
#include <node.h>
#include <v8.h>
 
using namespace v8;

Handle<Value> Method(const Arguments& args) {
  HandleScope scope;
  Local<String> code = args[0]->ToString();
  return scope.Close(code);
}

extern "C" void
init (Handle<Object> target)
{
  HandleScope scope;
  target->Set(String::NewSymbol("hello"),
        FunctionTemplate::New(Method)->GetFunction());
  //target->Set(String::New("hello"), String::New("world"));
}

//NODE_MODULE(hello, init)
