atp = {
    "ftp": "10.160.90.106",
    "os_image": "",
    "os_image_info": {
        "project": "FortiOS",
        "version": "7",
        "build": "0656",
        "file_pattern": "FGT_3501F-.*\\.out",
        "branch": "main"
    },
    "os_product": "FortiOS",
    "os_ver": "7.0.16dev",
    "os_build": "0656",
    "os_prefix": "FGT_3501F",
    "os_label": "Interim Build < Target Version >",
    "ips_image": "",
    "ips_image_info": {
        "project": "IPSengine",
        "version": "7",
        "build": "0183",
        "file_pattern": "flen-fos\\d+\\.\\d+-\\d\\.\\d{3}\\.pkg",
        "branch": "main"
    },
    "ips_ver": "7.0.16dev",
    "ips_build": "0183",
    "ips_label": "Interim Build",
    "config": "test-config-BMRK2",
    "config_file_id": "",
    "config_version": "",
    "config_build": "",
    "config_checksum": "",
    "signature": {
        "apdb": [{"version": "27.794", "file": "/apdb/apdb-700-27.794.pkg"}],
        "fmwp": [],
        "iotd": [],
        "isdb": [{"version": "27.794", "file": "/isdb/isdb-700-27.794.pkg"}],
        "nids": [{"version": "27.794", "file": "/nids/nids-700-27.794.pkg"}],
        "otdb": [],
        "otdp": [],
        "avdb": [{"version": "92.04693", "file": "/avdb/vsigupdate-OS7.0.0_92.04693.ETDB.High.pkg"}],
        "exdb": [{"version": "92.04510", "file": "/exdb/vsigupdate-OS7.0.0_92.04510.EXDB.pkg"}],
        "mmdb": [{"version": "92.04693", "file": "/mmdb/vsigupdate-OS7.0.0_92.04693.MMDB.pkg"}],
        "fldb": [{"version": "92.04693", "file": "/fldb/vsigupdate-OS7.0.0_92.04693.FLDB.pkg"}],
        "avai": [{"version": "2.16370", "file": "/avai/vsigupdate-OS7.0.0_2.16370.AVAI.pkg"}]
    },
    "signature_path": "signature/7.0"
}

# 生成文件名
os_file = f"{atp['os_prefix']}-v{atp['os_image_info']['version']}-build{atp['os_build']}-FORTINET.out"
print(str(os_file))
apdb_file = ', '.join(entry['file'] for entry in atp['signature']['apdb'])
ip = atp['ftp']
command_os = f'execute restore image tftp {os_file} {ip}'
command_apdb = f'execute restore ips tftp {apdb_file} {ip}'
print(command_os)