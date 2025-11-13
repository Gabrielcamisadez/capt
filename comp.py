#!/usr/bin/env python3


malwares = [
"011b04b3c8e9e7975ca405a57bcf82cdba69a85dec29ec59d523b767ffd9c603",
"0981a1461a7d823e2259eab4d0ef24bf1074ef10424e504e25b9d1380ed187f1",
"1a0af26749f5bc21732c53fc12f3a148215c8221cbeffe920411656f1ffe7500",
"21e7b73457e5954c4fb8aa569b379eeef6c244c51778f2fdbeff8380eb02a16d",
"276c4a5957597c342daeb4d90f542eab939fc2997cf4ec9720ce411972f6c879",
"291b2c9c4c1382a067da93eee4dd68bdecf535ed3b843d979622bc6849e904e4",
"2d441e416f8e0c228391bab6ebf8b4e038a2d09432bc2d6e73da47cfba4044fb",
"2d83c4d620866f4ae647ed6a70113686bb7b80b1a7bbdcf544fd0ffec105c4a6",
"3b68826e4a1d95b1dd58b3bf1095750f31a72d8bddd1dbb35e6547ac0cf4769b",
"46033323a729e608da731aec81de97ed1f0d673168690a803bfa630bd9954bc9",
"6d20bd31298569d7647a38a347915d1ff7da740e539417dcf82a8b3ed7b7f090",
"aad33a043da0073dc070942c3a15b3f62dc8013e416187cea5b4f37ae1f0f798",
"adb29d2eef4ce1911f79f20469f4279bd9124c3f05cd8648841e0175db3f37d6",
"b848cd959cb2543f3ec68701a2f64caf5fcc2f6e86b8f87f7ba1e9eabc436b30",
"bd62148637152396b757c8b106d5a62982bce9df12f0a6030dda9138e44e7328",
"c50b6ff360e5614d91f80a5e2d616a9d0d1a9984751bf251f065426a63dac0b5",
"c658f6f3e022102200e5a3a984398012cbaa629ba438fb3b5e639b8b86d62447",
"db94572d8802433ea2100b2eb840697d92c859dc28d5c63ae197eef1aeba72fb",
"dcdde53c50aef9531c9f59f341a4e2d59796cdd94a973f2c2a464b2cafed41f5",
"ed6875f870585873a57a5752686061182cd0129458f5e50ea87d64fbdde57f7d"
]

malwares_set = set(malwares)

eset_file = "hashs.txt"

encontrados = []

with open('hashs.txt', 'r') as file:
    for linha in file:
        eset_hash = linha.strip()

        if not eset_hash:
            continue

        if eset_hash in malwares_set:
            print(f"encontrado {eset_hash}")
            encontrados.append(eset_hash)

if encontrados:
    print(f"tottal encontrado {len(encontrados)}")
