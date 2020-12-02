use std::fs;
use std::str;
use std::convert::TryInto;
use serde_json::json;
use std::time::SystemTime;

extern crate base64;
extern crate hex;
extern crate reqwest;
extern crate nom;

// the below constants MUST be filled in
const JWT: &str = "";
// host, i.e. sharedcus.cus.attest.azure.net
const HOST: &str = "";
// quote to base off of
const ORIGINAL_QUOTE: &str = "";
// Collateral, aka runtime data
const COLLATERAL: &str = "";

//QUOTE STRUCTURE
// version:              le_u16    >> 0
// attestation_key_type: le_u16    >> 2
// _reserved_1:          take!(4)  >> 4
// qe_svn:               le_u16    >> 8
// pce_svn:              le_u16    >> 10
// qe_vendor_id:         take!(16) >> 12
// user_data:            take!(20) >> 28


// cpu_svn:     take!(16) >>  48
// miscselect:  le_u32    >>
// _reserved_1: take!(28) >>
// attributes:  take!(16) >>
// mrenclave:   take!(32) >>
// _reserved_2: take!(32) >>
// mrsigner:    take!(32) >>
// _reserved_3: take!(96) >>
// isv_prod_id: le_u16    >>
// isv_svn:     le_u16    >>
// _reserved_4: take!(60) >>
// report_data: take!(64) >> 368

// signature size: u32    >> 432

// isv_report_signature:       take!(64)                         >> 436
// attestation_key:            take!(64)                         >> 500
// qe_report:                  parse_report_body                 >> 564
// qe_report_signature:        take!(64)                         >> 948
// qe_authentication_data:     variable                          >> 1012
    // size:                   u16                               >> 1012
    // data:                   variable
// qe_certification_data:      variable
    // type:                   u16                               >> 1014 + auth_data_size
    // size:                   u32                               >> 1016 + auth_data_size
    // data:                   variable                          >> 1020 + auth_data_size

// >> 1020 + auth_data_size + cert_data_size

fn main() -> std::io::Result<()>{

    let bytes = &base64::decode_config(ORIGINAL_QUOTE,base64::URL_SAFE).unwrap();

    let client = reqwest::blocking::Client::builder()
        .timeout(None)
        .build().unwrap();

    // control
    send_request(&client,bytes,"control");

    // all )'s in the report data field
    let new_bytes = &replace_report_data(bytes);
    send_request(&client,new_bytes,"junkreportdata");

    //same quote, just set cert data size to min
    let new_bytes = &set_cert_data_size(bytes,u32::MIN);
    send_request(&client,new_bytes,"minsize");

    //same quote, just set cert data size to max
    let new_bytes = &set_cert_data_size(bytes,u32::MAX);
    send_request(&client,new_bytes,"maxsize");

    //same quote, just set cert data size to zero
    let new_bytes = &set_cert_data_size(bytes,0);
    send_request(&client,new_bytes,"zerosize");

    //all )'s in the cert data field, wrapped in BEGIN-CERTIFICATE / END-CERTIFICATE
    let new_bytes = &replace_cert_data_with_pem_wrapped_junk(bytes);
    let _quote = sgx_quote::Quote::parse(new_bytes).unwrap();
    send_request(&client,new_bytes,"pemwithjunkincertdata");

    //all )'s in the cert data field
    let new_bytes = &replace_cert_data_with_junk(bytes);
    send_request(&client,new_bytes,"totaljunkincertdata");

    //add 100 copies of the cert data field to the cert data field, and send 100 times
    let new_bytes = &duplicate_cert_data(bytes,100);
    for i in 0..100{
        let tag = &format!("duplicatecerts{}",i);
        send_request(&client,new_bytes,tag);
    }
    
    //add 5000 copies of the cert data field to the cert data field
    let new_bytes = &duplicate_cert_data(bytes,5000);
    send_request(&client,new_bytes,"extraduplicatedcertdata");

    //add 1000 copies of the cert data field to the cert data field, and increase the size by one
    let new_bytes = &duplicate_cert_data(bytes,1000);
    let cert_data_size = get_cert_data_size(new_bytes);
    let new_bytes = &set_cert_data_size(new_bytes,cert_data_size+1);
    send_request(&client,new_bytes,"extraduplicatedcertdataoffbyone");

    //add 1000 copies of the cert data field to the cert data field, and decrease the size by one
    let new_bytes = &duplicate_cert_data(bytes,1000);
    let cert_data_size = get_cert_data_size(new_bytes);
    let new_bytes = &set_cert_data_size(new_bytes,cert_data_size-1);
    send_request(&client,new_bytes,"extraduplicatedcertdataoffbyoneminus");

    //replace the middle of the cert data field with junk
    let new_bytes = &obfuscate_cert_data(bytes);
    send_request(&client,new_bytes,"obfuscatedcertdata");
    
    Ok(())
}
fn encode_bytes(bytes: &[u8]) -> String{
    return base64::encode_config(bytes,base64::URL_SAFE);
}
fn send_request(client: &reqwest::blocking::Client,bytes: &[u8],tag: &str){
    let raw_quote = encode_bytes(bytes);
    let json = json!(
        {
            "quote":raw_quote,
            "runtimeData": 
            {
                "data": COLLATERAL,
                "dataType":"Binary"
            }
        });
    let now = SystemTime::now();
    println!("sending {}...",tag);
    let uri: &str = &format!("https://{0}/attest/SgxEnclave?api-version=2020-10-01&casaba={1}",HOST,tag);
    let res = client.post(uri)
        .bearer_auth(JWT) 
        .json(&json)
        .send().unwrap();
    println!("{:?}",SystemTime::now().duration_since(now).unwrap());
    println!("{:?}",res.status());
    println!("{:?}",res.text())
}
fn get_bytes_from_file(fname: &str) -> Vec<u8>{
    let data = fs::read_to_string(fname).expect("Unable to read file");
    let bytes = base64::decode_config(data,base64::URL_SAFE).unwrap();
    return bytes;
}
fn display_report(quote: sgx_quote::Quote){
    println!("cpu_svn: {}",hex::encode(quote.isv_report.cpu_svn));
    println!("miscselect: {}",quote.isv_report.miscselect);
    println!("attributes: {}",hex::encode(quote.isv_report.attributes));
    println!("mrenclave: {}",hex::encode(quote.isv_report.mrenclave));
    println!("mrsigner: {}",hex::encode(quote.isv_report.mrsigner));
    println!("isv_prod_id: {}",quote.isv_report.isv_prod_id);
    println!("isv_svn: {}",quote.isv_report.isv_svn);
    println!("report_data: {}",hex::encode(quote.isv_report.report_data));
    
    match quote.signature {
        sgx_quote::Signature::EcdsaP256
        {   
            qe_authentication_data: auth_data, 
            isv_report_signature: _,
            attestation_key: _,
            qe_report: _,
            qe_report_signature: _,
            qe_certification_data: cert_data
        } =>   
            {
                println!("auth_data: {}",hex::encode(auth_data));
                match cert_data
                {
                    sgx_quote::QeCertificationData::CertChain(data) => 
                    {
                        println!("cert_data: {}",hex::encode(data));
                    },
                    _ => { println!("unhandled type!!")}
                };
            }
    };
}
fn verify_size(raw: &[u8]){

    println!("total size: {}",raw.len());

    println!("header size: 48"); //these should be constant.. unless you're fuzzing them...
    println!("body size: 384");
    println!("signature size size: 4");
    println!("pre-signature size: 436");

    let signature_size = u32::from_le_bytes(raw[(432)..(432+4)].try_into().expect("bad"));
    println!("signature size: {}",signature_size);

    let auth_data_size = get_auth_data_size(raw);
    println!("auth data size: {}",auth_data_size);

    let cert_data_size = u32::from_le_bytes(raw[(1016+auth_data_size)..(1016+auth_data_size+4)].try_into().expect("bad"));
    println!("cert data size: {}",cert_data_size);

}
fn get_auth_data_size(raw: &[u8]) -> usize{
    return usize::from(u16::from_le_bytes(raw[(1012)..(1012+2)].try_into().expect("bad")));
}
fn get_cert_data_size(raw: &[u8]) -> u32{
    let auth_data_size = get_auth_data_size(raw);
    return u32::from_le_bytes(raw[(1016+auth_data_size)..(1016+auth_data_size+4)].try_into().expect("bad"));
}
fn replace_report_data(raw: &[u8]) -> Vec<u8>{
    const SIZE: usize = 64;
    let new_data: &[u8;SIZE] = &[ 41 ; SIZE];
    let pre = &raw[0 .. 368];
    let post = &raw[432 ..];
    let new = [pre,new_data,post].concat();
    return new;
}
fn replace_user_data(raw: &[u8]) -> Vec<u8>{
    let new_data: &[u8;20] = &[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
    let pre = &raw[0 .. 28];
    let post = &raw[48 ..];
    let new = [pre,new_data,post].concat();
    return replace_signature_size(&new);
}
fn obfuscate_cert_data(raw: &[u8]) -> Vec<u8>{
    
    let auth_data_size = get_auth_data_size(raw);
    let new_data = &raw[1020+auth_data_size+20..1020+auth_data_size+40];
    let pre = &raw[0..1020+auth_data_size+20];
    let post = &raw[1020+auth_data_size+20..];
    let new = [pre,new_data,post].concat();

    return replace_signature_size(&replace_cert_data_size(&new));
}
fn replace_cert_data_with_junk(raw: &[u8]) -> Vec<u8>{
    const SIZE: usize = 100000;
    let new_data: &[u8;SIZE] = &[ 41 ; SIZE];
    let auth_data_size = get_auth_data_size(raw);
    let pre = &raw[0 .. (1020 +auth_data_size)];
    let new_size = &((new_data.len()) as u32).to_le_bytes();
    let new = [pre,new_size,new_data].concat();
    return replace_signature_size(&new);
}
fn replace_cert_data_with_pem_wrapped_junk(raw: &[u8]) -> Vec<u8>{
    const SIZE: usize = 100000;
    let begin = "-----BEGIN CERTIFICATE----- ";
    let end = "-----END CERTIFICATE-----";
    let middle: &[u8;SIZE] = &[ 41 ; SIZE];
    let middle_str = str::from_utf8(middle).unwrap();
    let new_data_str = [begin,middle_str,end].join("\n");
    //println!("{}",new_data_str);
    let new_data = new_data_str.as_bytes();
    //let new_data = &get_bytes_from_file("./fixtures/fake_cert.txt");

    let auth_data_size = get_auth_data_size(raw);
    let pre = &raw[0 .. (1020 +auth_data_size)];
    let new = [pre,new_data].concat();
    return replace_signature_size(&replace_cert_data_size(&new));
}
fn duplicate_cert_data(raw: &[u8], iterations:usize) -> Vec<u8>{
    let auth_data_size = get_auth_data_size(raw);
    let post = &raw[1020+auth_data_size..];
    let mut old: Vec<u8>;
    let mut new = raw;
    for _ in 0..iterations{
        old = [new,post].concat();
        new = &old;
    }
    return replace_signature_size(&replace_cert_data_size(new));
}

fn set_cert_data_size(raw: &[u8], size: u32) -> Vec<u8>{
    let auth_data_size = get_auth_data_size(raw);
    let pre = &raw[0..1016+auth_data_size];
    let post = &raw[1020+auth_data_size..];
    let size_bytes = &size.to_le_bytes();
    return [pre,size_bytes,post].concat();
}
fn replace_cert_data_size(raw: &[u8]) -> Vec<u8>{
    let auth_data_size = get_auth_data_size(raw);
    let pre = &raw[0..1016+auth_data_size];
    let post = &raw[1020+auth_data_size..];
    let size = &((post.len()) as u32).to_le_bytes();
    return [pre,size,post].concat();
}
fn replace_signature_size(raw: &[u8]) -> Vec<u8>{
    let pre = &raw[0..432];
    let post = &raw[436..];
    let sig_size = &((post.len()) as u32).to_le_bytes();
    return [pre,sig_size,post].concat();


}

