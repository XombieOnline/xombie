use crypto::md5::Md5;
use crypto::digest::Digest;

pub fn md5(bytes: &[u8]) -> Vec<u8> {
    let mut md5 = Md5::new();
    let mut output = vec![0; md5.output_bytes()];
    md5.input(bytes);
    md5.result(&mut output);
    return output;
}
