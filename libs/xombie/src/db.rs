use std::{net::IpAddr, num::ParseIntError};

use tokio_postgres::{Client, NoTls};

use xbox_sys::account::Xuid;
use xbox_sys::config::{MacAddress, SerialNumber};
use xbox_sys::crypto::SymmetricKey;

pub async fn connect_db_client(pg_addr: &str, pg_port: u16, pg_user: &str, pg_password: &str) -> Result<Client, tokio_postgres::Error> {
    let pg_connection_string =
        format!("host={} port={} user={} password={} dbname=xombie", pg_addr, pg_port, pg_user, pg_password);

    println!("\"{}\"", pg_connection_string);

    let (pg_client, pg_connection) = 
        tokio_postgres::connect(&pg_connection_string, NoTls)
        .await
        .unwrap();

    tokio::spawn(async move { 
        pg_connection.await.unwrap();
    });

    Ok(pg_client)
}

#[derive(Debug)]
pub struct MachineInfo {
    pub xuid: Xuid,
    pub serial_number: SerialNumber,
    pub mac_address: MacAddress,
}

impl MachineInfo {
    pub fn gamertag(&self) -> String {
        format!("SN.{}", self.serial_number)
    }
}

#[derive(Debug)]
pub enum BoxInfoGetError {
    NotFound,
    MoreThanOneEntry,
    Pg(tokio_postgres::Error),
    CannotParseXuid(ParseIntError),
    CannotParseSerial,
    CannotParseOnlineKey,
    CannotParseHddKey,
}

impl From<tokio_postgres::Error> for BoxInfoGetError {
    fn from(pg_err: tokio_postgres::Error) -> Self {
        BoxInfoGetError::Pg(pg_err)
    }
}

impl From<ParseIntError> for BoxInfoGetError {
    fn from(parse_error: ParseIntError) -> Self {
        BoxInfoGetError::CannotParseXuid(parse_error)
    }
}

fn xuid_string(xuid: Xuid) -> String {
    format!("{:016x}", xuid.0)
}

pub async fn get_machine_info_for_serial_number(client: &Client, serial_number: &str) -> Result<MachineInfo, BoxInfoGetError> {
    let rows = client.query(
            "SELECT * FROM machines WHERE serial = $1",
            &[&serial_number.to_owned()])
        .await?;

    let row = match rows.len() {
        0 => return Err(BoxInfoGetError::NotFound),
        1 => &rows[0],
        _ => return Err(BoxInfoGetError::MoreThanOneEntry),
    };

    let xuid: String = row.get(0);
    let serial_number: String = row.get(1);
    let mac_address: eui48::MacAddress = row.get(2);

    let xuid = Xuid(u64::from_str_radix(&xuid, 16)?);
    let serial_number = SerialNumber::parse(&serial_number)
        .ok_or(BoxInfoGetError::CannotParseSerial)?;
    let mac_address = xbox_sys::config::MacAddress(mac_address.to_array());

    Ok(MachineInfo {
        xuid,
        serial_number,
        mac_address,
    })
}

#[derive(Debug, PartialEq)]
pub enum KeyType {
    HddKey,
    OnlineKey,
    ClientMasterKey,
    TgsClientSessionKey,
    SgServiceSessionKey,
}

impl KeyType {
    fn db_type_str(&self) -> String {
        use KeyType::*;
        match self {
            HddKey =>              "hdd_key",
            OnlineKey =>           "online_key",
            ClientMasterKey =>     "client_master_key",
            TgsClientSessionKey => "tgs_client_session_key",
            SgServiceSessionKey => "sg_service_session_key",
        }.to_owned()
    }
}

#[derive(Debug)]
pub enum GetKeyForXuidError {
    NoKeysPresent,
    Pg(tokio_postgres::Error),
    UnableToParseKey,
}

pub async fn get_key_for_xuid(client: &Client, xuid: Xuid, key_type: KeyType) -> Result<(SymmetricKey, i32), GetKeyForXuidError> {
    let xuid_str = xuid_string(xuid);

    let rows = client.query(
        "SELECT kvno, key FROM client_keys WHERE xuid = $1 AND key_type = $2 ORDER BY kvno DESC LIMIT 1",
        &[&xuid_str, &key_type.db_type_str()]
    ).await
    .map_err(|err| GetKeyForXuidError::Pg(err))?;

    if rows.len() != 1 {
        return Err(GetKeyForXuidError::NoKeysPresent);
    }

    let row = &rows[0];

    let kvno: i32 = row.get(0);
    let key: String = row.get(1);

    let key = SymmetricKey::parse_str(&key)
        .ok_or(GetKeyForXuidError::UnableToParseKey)?;

    Ok((key, kvno))
}

pub async fn get_xuid_for_gamertag(client: &Client, gamertag: String) -> Option<Xuid> {
    let rows = client.query(
        "SELECT xuid FROM clients WHERE gamertag = $1 LIMIT 1",
        &[&gamertag]
    ).await
    .ok()?;

    if rows.len() != 1 {
        return None;
    }

    let xuid: String = rows[0].get(0);

    Some(Xuid(
        u64::from_str_radix(&xuid, 16)
        .ok()?
    ))
}

#[derive(Debug)]
pub struct ClusterInfo {
    pub kdc_nodes: Vec<[u8;4]>,
    pub sg_nodes: Vec<[u8;4]>,
}

#[derive(Debug)]
pub enum ReadClusterInfoError {
    Pg(tokio_postgres::Error),
}

impl From<tokio_postgres::Error> for ReadClusterInfoError {
    fn from(other: tokio_postgres::Error) -> Self {
        ReadClusterInfoError::Pg(other)
    }
}

pub async fn get_cluster_addrs(client: &Client) -> Result<ClusterInfo, ReadClusterInfoError> {
    let mut cluster_info = ClusterInfo {
        kdc_nodes: vec![],
        sg_nodes: vec![],
    };

    let kdc_rows = client.query("SELECT external_ip FROM kdc_nodes;", &[]).await?;
    for row in kdc_rows {
        let ip: IpAddr = row.get(0);

        if let IpAddr::V4(ip) = ip {
            cluster_info.kdc_nodes.push(ip.octets());
        }
    }

    for row in client.query("SELECT external_ip FROM sg_nodes;", &[]).await? {
        let ip: IpAddr = row.get(0);

        if let IpAddr::V4(ip) = ip {
            cluster_info.sg_nodes.push(ip.octets());
        }
    }

    Ok(cluster_info)
}