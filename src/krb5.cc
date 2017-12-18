#include <sys/stat.h>
#include <cstdio>
#include <cstring>
#include "krb5.h"

static gss_OID_desc _gss_mech_spnego = {6, (void*)"\x2b\x06\x01\x05\x05\x02"}; //Spnego OID: 1.3.6.1.5.5.2
static const gss_OID GSS_MECH_SPNEGO= &_gss_mech_spnego; //gss_OID == gss_OID_desc*

bool exists(const char* path){
  struct stat buffer;
  return (stat(path, &buffer) == 0);
}

Krb5::Krb5(){
  spnego_token=NULL;
  client_principal=NULL;
  cache=NULL;
  err=0;
  err = krb5_init_secure_context(&context);
  cred = (krb5_creds*)malloc(sizeof(krb5_creds));
  memset(cred, 0, sizeof(krb5_creds));
}

Krb5::~Krb5() {
  cleanup();
}

//Kinit function
krb5_error_code Krb5::init(const char* user, const char* realm){
  if(!realm || !user){
    err = -1;
    return err;
  }
  int len_realm = strlen(realm);
  int len_user = strlen(user);
  if(!len_realm || !len_user) {
    err = -1;
    return err;
  }
  //Create user principal (user@realm) from user and realm
  err = krb5_build_principal(context, &client_principal, len_realm, realm, user, NULL);
  if(err) {
    return cleanup();
  }
  //Get default credential cache
  err = krb5_cc_default(context, &cache);
  if(err) {
    return cleanup();
  }
  //If default cache does'nt exist, we initialize it
  if(!exists(krb5_cc_get_name(context, cache))){
    err = krb5_cc_initialize(context, cache, client_principal);
    if(err) {
      return cleanup();
    }
  }
  return err;
}

krb5_error_code Krb5::destroy(const char* name){
  krb5_ccache cache;
  if(name){
    err = krb5_cc_resolve(context, name, &cache);
    if(err) return err;
  }
  else{
    err = krb5_cc_default(context, &cache);
    if(err) return err;
  }
  err = krb5_cc_destroy(context, cache);
  return err;
}

krb5_error_code Krb5::cleanup(int level) {
  if(context)
    krb5_free_context(context);
  if(client_principal)
    krb5_free_principal(context,client_principal);
  if(cache)
    krb5_cc_close(context, cache);
  if(spnego_token)
    free(spnego_token);
  return 0;
}

void Krb5::init_custom_error(krb5_error_code errCode, const char* msg){
  krb5_set_error_message(context, errCode, msg);
}

void Krb5::set_error(krb5_error_code errCode){
  err = errCode;
}

const char* Krb5::get_error_message(){
  return krb5_get_error_message(context, err);
}

krb5_error_code Krb5::get_credentials_by_keytab(const char* keytabName) {
  char kt[2048];
  krb5_keytab keytab;
  if(!err){
    if(keytabName){
      int len = strlen(keytabName);
      if(len) {
        strcpy(kt,"FILE:");
        strcat(kt,keytabName);
        err = krb5_kt_resolve(context, kt, &keytab);
      }
      else {
        err = krb5_kt_default(context,&keytab);
      }
    }
    //SI le path n'est pas précisé, on récupère la keytab par défaut
    else {
      err = krb5_kt_default(context,&keytab);
    }
    if(err) {
      return cleanup();
    }
    err = krb5_get_init_creds_keytab(context, cred, client_principal, keytab, 0, NULL, NULL);
    if(err) {
      return cleanup();
    }
    err = krb5_verify_init_creds(context,cred,NULL, NULL, NULL, NULL);
    if(err) {
      cleanup();
      return err;
    }
    err = krb5_cc_store_cred(context, cache, cred);

    if(err) {
      cleanup();
      return err;
    }
  }
  return err;
}

krb5_error_code Krb5::get_credentials_by_password(const char* password) {
  if(!err){
    err = krb5_get_init_creds_password(context,cred,client_principal,password, NULL, NULL, 0, NULL, NULL);
    if(err) {
      cleanup();
      return err;
    }
    err = krb5_cc_store_cred(context, cache, cred);
    if(err) {
      cleanup();
      return err;
    }
  }
  return err;
}

OM_uint32 Krb5::import_name(const char* principal, gss_name_t* desired_name) {
  OM_uint32 ret;
  gss_buffer_desc service;
  service.length = strlen(principal);
  service.value = (char*)principal;
  ret=gss_import_name((OM_uint32*)&err, &service,GSS_C_NT_HOSTBASED_SERVICE, desired_name);
  return ret;
}
/*
Get the Base64-encoded token
*/
OM_uint32 Krb5::generate_spnego_token(const char* server) {
  gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
  gss_buffer_desc input_buf,output_buf;
  gss_name_t target_name;
  OM_uint32 gss_err;
  if(spnego_token){
    free(spnego_token);
  }
  gss_err = import_name(server,&target_name);
  if(gss_err) {
    return cleanup();
  }
  gss_err = gss_init_sec_context((OM_uint32*)&err,
                  GSS_C_NO_CREDENTIAL,
                  &gss_context,
                  target_name,
                  GSS_MECH_SPNEGO,
                  GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                  GSS_C_INDEFINITE,
                  GSS_C_NO_CHANNEL_BINDINGS,
                  &input_buf,
                  NULL,
                  &output_buf,
                  NULL,
                  NULL);
  if(!(GSS_ERROR(gss_err) || err)){
    char token_buffer[2048];
    encode64((char*)output_buf.value,token_buffer,output_buf.length);
    spnego_token = new char[strlen(token_buffer)+1];
    strcpy(spnego_token, token_buffer);
  }
  else{
    if(GSS_ERROR(gss_err) && !err){
      char token_buffer[2048];
      OM_uint32 message_context;
      OM_uint32 min_status;
      gss_buffer_desc status_string;
      message_context = 0;
      token_buffer[0] = '\0';
      do {
        gss_display_status(
              &min_status,
              gss_err,
              GSS_C_GSS_CODE,
              GSS_C_NO_OID,
              &message_context,
              &status_string);
        strcat(token_buffer, (char *)status_string.value);
        gss_release_buffer(&min_status, &status_string);
      } while (message_context != 0);
      init_custom_error(gss_err,token_buffer);
      set_error(gss_err);
    }
    spnego_token = NULL;
  }
  return gss_err;
}
