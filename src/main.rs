use std::fs;
extern crate base64;
extern crate hex;
use std::convert::TryInto;

extern crate nom;

fn main() -> std::io::Result<()>{
    let bytes = &get_bytes_from_file(&"./fixtures/sgx_quote.txt");
    
    
    println!("OLD SIZES");
    verify_size(bytes);
    //let new_bytes = &replace_cert_data(bytes);
    let new_bytes = &replace_user_data(bytes);
    println!("\nNEW SIZES");
    verify_size(new_bytes);

    let quote = sgx_quote::Quote::parse(new_bytes).unwrap();
    display_report(quote);

    let data = base64::encode_config(new_bytes,base64::URL_SAFE);
    println!("new data: {}",data);
    Ok(())
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
// report_data: take!(64) >>

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

fn replace_user_data(raw: &[u8]) -> Vec<u8>{
    let new_data: &[u8;20] = & [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
    let pre = &raw[0 .. 28];
    let post = &raw[48 ..];
    let new = [pre,new_data,post].concat();
    return replace_signature_size(&new);
}

fn replace_cert_data(raw: &[u8]) -> Vec<u8>{
    //let new_data: &[u8;4] = &[ 1 , 1 , 1 ,1];
    let new_data = &get_bytes_from_file("./fixtures/fake_cert.txt");

    let auth_data_size = get_auth_data_size(raw);
    let pre = &raw[0 .. (1016 +auth_data_size)];
    let new_size = &((new_data.len()) as u32).to_le_bytes();
    let new = [pre,new_size,new_data].concat();
    return replace_signature_size(&new);
}
fn replace_signature_size(raw: &[u8]) -> Vec<u8>{
    let pre = &raw[0..432];
    let post = &raw[436..];
    let sig_size = &((post.len()) as u32).to_le_bytes();
    return [pre,sig_size,post].concat();


}

