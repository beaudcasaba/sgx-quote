use std::fs;
extern crate base64;
extern crate hex;

fn main() -> std::io::Result<()>{
    let data = fs::read_to_string("./fixtures/sgx_quote.txt").expect("Unable to read file");
    let bytes = base64::decode_config(data,base64::URL_SAFE).unwrap();
    let c: &[u8] = &bytes; // c: &[u8]
    let quote = sgx_quote::Quote::parse(c).unwrap();


    println!("cpu_svn: {}",hex::encode(quote.isv_report.cpu_svn));
    println!("miscselect: {}",quote.isv_report.miscselect);
    println!("attributes: {}",hex::encode(quote.isv_report.attributes));
    println!("mrenclave: {}",hex::encode(quote.isv_report.mrenclave));
    println!("mrsigner: {}",hex::encode(quote.isv_report.mrsigner));
    println!("isv_prod_id: {}",quote.isv_report.isv_prod_id);
    println!("isv_svn: {}",quote.isv_report.isv_svn);
    println!("report_data: {}",hex::encode(quote.isv_report.report_data));
    Ok(())
}
