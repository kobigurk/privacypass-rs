pub use amcl::nist256 as curve;

#[derive(Serialize, Deserialize)]
pub struct ClientRequestWrapper {
	pub bl_sig_req: String,
	pub host: String,
	pub http: String,
}

#[derive(Serialize, Deserialize)]
pub struct ClientRequest {
	#[serde(rename = "type")]
	pub type_f: String,
	pub contents: Vec<String>,
}
