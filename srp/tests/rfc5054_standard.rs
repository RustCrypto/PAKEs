use hex_literal::hex;
use num_bigint::BigUint;
use sha2::Sha256;
use srp::client::SrpClient;
use srp::groups::G_2048;
use srp::server::SrpServer;
use srp::utils::{compute_hash, compute_k, compute_u};

#[test]
#[allow(clippy::many_single_char_names)]
fn rfc5054_standard() {
    let i = b"";
    let p = hex!("CCAF1BCA 820E8E6B 392C0EBA 7014CC9C DF49A650 84B39A53 834CC090 92BCDA20");
    let s = hex!("BC01D972 31E5A4BC 79171C6D 83783FF2");
    let group = &G_2048;

    let k = compute_k::<Sha256>(group);

    assert_eq!(
        k.to_bytes_be(),
        hex!("05B9E8EF 059C6B32 EA59FC1D 322D37F0 4AA30BAE 5AA9003B 8321E21D DB04E300"),
        "bad k value"
    );

    let identity_hash = SrpClient::<Sha256>::compute_identity_hash(i, &p);
    let x = SrpClient::<Sha256>::compute_x(identity_hash.as_slice(), &s);

    assert_eq!(
        x.to_bytes_be(),
        hex!("FD1709C7 30244792 F33348CB FBBD4AB4 39AC8090 FCDDC474 46244073 0D85ADDB"),
        "bad x value"
    );

    let client = SrpClient::<Sha256>::new_with_options(group, true, true);
    let v = client.compute_v(&x);

    assert_eq!(
        v.to_bytes_be(),
        hex!(
            "
         A2E59E34 4EC9AB6D 611BFC12 4A2E5DC7 46174702 9AC44A6F 6A8DB9E2
         7326A5CB E370C469 A20D59CD 63FA13E4 1F0F1968 61A0AA3A 778AB5F5
         2A0D57E9 BC3E9494 7ACDA1BD 3E62785D DB51FCE1 D2A34C87 E95CAD5A
         30731035 269E72AF 235E4537 62F94011 C965E1D3 F940A196 43B56810
         D7CD38AE 4DBB7CFF 80E529FE E33CBB88 C7877096 62342D98 314687BF
         0A5B0AE2 E6595B9A DC61B1BE 691E3176 62A01A24 BE963C70 8565694F
         575DCEA2 791364C7 465B1BD4 6D8BC9F7 53F3F6E5 C55491F2 080D00D5
         40F6E247 53AFB477 C33BC117 A0D6551A 16026D96 22F3AD50 6C379EFD
         85A075E7 C6D0DA46 442D6084 7095D43A 3E3C5EC2 6F523479 B3F2902B
         641A7B92
            "
        ),
        "bad v value"
    );

    let a = BigUint::from_bytes_be(&hex!(
        "
    81010101 01010101 01010101 01010101 01010101 01010101 01010101
    01010101
        "
    ));

    let b = BigUint::from_bytes_be(&hex!(
        "
    E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1
    05284D20
        "
    ));

    let a_pub = client.compute_a_pub(&a);

    assert_eq!(
        a_pub.to_bytes_be(),
        hex!(
            "
         01F9D75A 9DF8AC07 FB3684C4 DDF9ABD9 4CC03C10 1A381976 F16C92B5
         8083BB98 4137AD44 7D815819 529E0313 FCC4EDD4 5F31D033 CBC0FB4B
         F0CBB75A B0A2A10C 4C0C1C23 A62BA798 AB308818 C94F017C 2015BD3A
         4B2334B0 E2125F57 E12A2D31 936856B2 7BE1A615 8D32FC65 48A6B4BB
         62E63A13 8EF89664 CC1F43E7 457DE565 E1551F34 29A4B73A 7FAB0D9D
         821EF749 7A8A1D84 D637FA8E 443F57CE AF12D0B0 54A67726 3D7C15A4
         C88D87B9 136684BA 4AAB3466 524D9A47 30FBE924 1194B3E4 E61EB9A7
         67401AA3 E2D66AD0 B07CFF63 B41CD665 E0EC8BC2 75D16A49 E6ECAC4F
         2BB3AF76 BC2CBA64 83B665A6 CA804DB8 5093B091 77114E70 9DD8DFB1
         7A8B98CD
            "
        ),
        "bad a_pub value"
    );

    let server = SrpServer::<Sha256>::new(group);
    let b_pub = server.compute_b_pub(&b, &k, &v);

    assert_eq!(
        b_pub.to_bytes_be(),
        hex!(
            "
         7F75618C 8C3EC5D7 CDD11D6A C2C24157 0D3254FA 39CFF9C0 DBDD39BC
         B6161B2D 12FEE512 0814D17C 6CD56E37 EC9AFC86 8213C60F 672CA6D7
         436AEE09 11F59AC6 30DAE4F0 70B15E84 86200B1B 0163900D 2EBB612E
         963F1AC8 E083F70F E5484F83 559C11A2 C1936C79 361FCCA7 E9B21192
         14416D3F 487C3874 A76D3B23 29A0690B DA774225 104D06B9 418D6207
         75D64CE8 54004E07 50F64299 D13B5AA2 3AEBF69B 56814E17 EBC1784B
         1881E6BE 651DEABE 2C6E78DE 0A84C032 0DE266B4 1444DC2F 397F0436
         8B62BDDE F573D274 EA304F40 B7CDB74A 345AD036 C5ED746F B3F7D627
         597FC9C6 A453BF05 D11185E0 EBB74797 D4490903 2D9749F7 8AB8ED63
         FCBFCA58
            "
        ),
        "bad b_pub value"
    );

    let u = compute_u::<Sha256>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());

    assert_eq!(
        u.to_bytes_be(),
        hex!("6B527E30 667D330D 84874755 1E17E271 BA465393 CA48264C D37E59DF 18267B37"),
        "bad u value"
    );

    assert_eq!(
        compute_hash::<Sha256>(
            &client
                .compute_premaster_secret(&b_pub, &k, &x, &a, &u)
                .to_bytes_be()
        )
        .as_slice(),
        hex!(
            "
         CD315DD4 2652B85B FFDD273E EF98FEDE 3C77E0AE 07898ABE A60FEEA6
         EE706231
            "
        ),
        "bad client premaster"
    );

    assert_eq!(
        compute_hash::<Sha256>(
            &server
                .compute_premaster_secret(&a_pub, &v, &u, &b)
                .to_bytes_be()
        )
        .as_slice(),
        hex!(
            "
         CD315DD4 2652B85B FFDD273E EF98FEDE 3C77E0AE 07898ABE A60FEEA6
         EE706231
            "
        ),
        "bad server premaster"
    );
}
