#include "worker.h"
#include "bind.h"

Worker::Worker(Krb5* nkrb, Nan::Callback* cb, char** args, int args_length, void (*func)(Krb5*, const char* const*, int), bool ret) : Nan::AsyncWorker(cb) {
  k = nkrb;
  args_length = args_length;
  args = args;
  func = func;
  ret = ret;
}

Worker* Worker::Create(const Nan::FunctionCallbackInfo<v8::Value>& info, void (*func)(Krb5*, const char* const*, int), bool ret) {
  int length = info.Length()-1;
  Krb5* k = ((Krb5Wrap*)Nan::ObjectWrap::Unwrap<Krb5Wrap>(info.This()))->Unwrap();
  if (!k) return;
  Nan::Callback* callback = new Nan::Callback(info[length].As<v8::Function>());
  char** args = (length>0)?new char*[length]:NULL;
  int i;
  for(i=0; i<length; i++){
    v8::String::Utf8Value arg(info[i]);
    args[i] = new char[strlen(*arg)];
    strcpy(args[i], *arg);
  }
  return new Worker(k, callback, args, length, func, ret);
}

Worker::~Worker() {
  int i;
  for(i=0; i<args_length; i++){
    free(args[i]);
  }
  if(args) free(args);
}

void Worker::Execute() {
  if (!k) return;
  (*func)(k, args, args_length);
}

void Worker::HandleOKCallback() {
  if (!k) return;
  if(ret){
    if(k->err){
      v8::Local<v8::Value> argv[] = {Nan::Error(k->get_error_message()), Nan::Null()};
      callback->Call(2,argv);
    }
    else{
      v8::Local<v8::Value> argv[] = {Nan::Null(), Nan::New(k->spnego_token).ToLocalChecked()};
      callback->Call(2,argv);
    }
  }
  else{
    if(k->err){
      v8::Local<v8::Value> argv[] = {Nan::Error(k->get_error_message())};
      callback->Call(1,argv);
    }
    else{
      v8::Local<v8::Value> argv[] = {Nan::Null()};
      callback->Call(1,argv);
    }
  }
}
