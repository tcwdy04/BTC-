import hashlib
import base58

def hash160(data):
    """计算数据的 RIPEMD160(SHA256(data))"""
    sha256 = hashlib.sha256(data).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    return ripemd160.digest()

def public_key_to_address_info(public_key_hex):
    """
    从公钥生成完整的地址信息
    """
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # 验证公钥长度
        if len(public_key_bytes) not in [33, 65]:
            return None, "公钥长度无效。压缩公钥应为33字节(66字符)，非压缩公钥应为65字节(130字符)"
        
        # 验证公钥格式
        if len(public_key_bytes) == 33 and public_key_bytes[0] not in [0x02, 0x03]:
            return None, "压缩公钥应以02或03开头"
        elif len(public_key_bytes) == 65 and public_key_bytes[0] != 0x04:
            return None, "非压缩公钥应以04开头"
        
        # 计算公钥哈希
        pubkey_hash = hash160(public_key_bytes)
        
        # 主网 P2PKH 地址 (以1开头)
        mainnet_payload = b'\x00' + pubkey_hash
        mainnet_checksum = hashlib.sha256(hashlib.sha256(mainnet_payload).digest()).digest()[:4]
        mainnet_address = base58.b58encode(mainnet_payload + mainnet_checksum).decode('ascii')
        
        # 测试网 P2PKH 地址 (以m或n开头)
        testnet_payload = b'\x6f' + pubkey_hash
        testnet_checksum = hashlib.sha256(hashlib.sha256(testnet_payload).digest()).digest()[:4]
        testnet_address = base58.b58encode(testnet_payload + testnet_checksum).decode('ascii')
        
        # P2SH-P2WPKH 地址 (嵌套隔离见证，以3开头)
        p2sh_payload = b'\x05' + hash160(b'\x00\x14' + pubkey_hash)
        p2sh_checksum = hashlib.sha256(hashlib.sha256(p2sh_payload).digest()).digest()[:4]
        p2sh_address = base58.b58encode(p2sh_payload + p2sh_checksum).decode('ascii')
        
        # Bech32 地址 (原生隔离见证，需要额外的库，这里简化处理)
        # 实际应用中推荐使用 bech32 库
        
        return {
            'public_key': public_key_hex,
            'public_key_length': len(public_key_bytes),
            'public_key_format': '压缩' if len(public_key_bytes) == 33 else '非压缩',
            'public_key_hash': pubkey_hash.hex(),
            'mainnet_p2pkh': mainnet_address,
            'testnet_p2pkh': testnet_address,
            'p2sh_nested_segwit': p2sh_address
        }, None
        
    except Exception as e:
        return None, f"处理公钥时出错: {str(e)}"

def validate_bitcoin_address(address):
    """
    验证比特币地址的有效性
    """
    try:
        # Base58 解码
        decoded = base58.b58decode(address)
        
        if len(decoded) != 25:
            return False, "地址长度不正确"
        
        # 提取版本、载荷和校验和
        version = decoded[0]
        payload = decoded[1:21]
        checksum = decoded[21:]
        
        # 验证校验和
        calculated_checksum = hashlib.sha256(hashlib.sha256(decoded[:21]).digest()).digest()[:4]
        
        if checksum == calculated_checksum:
            # 判断地址类型
            if version == 0x00:
                return True, "主网 P2PKH 地址 (1...)"
            elif version == 0x05:
                return True, "主网 P2SH 地址 (3...)"
            elif version == 0x6f:
                return True, "测试网 P2PKH 地址 (m/n...)"
            elif version == 0xc4:
                return True, "测试网 P2SH 地址 (2...)"
            else:
                return True, f"未知类型的地址 (版本字节: {hex(version)})"
        else:
            return False, "校验和无效"
            
    except Exception as e:
        return False, f"地址格式错误: {e}"

def main():
    """
    主函数 - 支持手动输入公钥
    """
    print("=" * 60)
    print("比特币公钥到地址转换工具")
    print("=" * 60)
    
    while True:
        print("\n请选择操作:")
        print("1. 从公钥生成地址")
        print("2. 验证比特币地址")
        print("3. 退出程序")
        
        choice = input("\n请输入选项 (1/2/3): ").strip()
        
        if choice == '1':
            print("\n" + "-" * 40)
            print("公钥到地址转换")
            print("-" * 40)
            
            # 获取公钥输入
            public_key_hex = input("请输入公钥 (十六进制格式): ").strip()
            
            # 清理输入
            public_key_hex = public_key_hex.replace(" ", "").replace("\n", "").replace("\t", "")
            
            if not public_key_hex:
                print("错误: 公钥不能为空")
                continue
                
            # 处理公钥
            result, error = public_key_to_address_info(public_key_hex)
            
            if error:
                print(f"\n❌ 错误: {error}")
                continue
                
            # 显示结果
            print(f"\n✅ 公钥信息:")
            print(f"   公钥: {result['public_key']}")
            print(f"   长度: {result['public_key_length']} 字节")
            print(f"   格式: {result['public_key_format']}")
            print(f"   哈希: {result['public_key_hash']}")
            
            print(f"\n📫 生成的地址:")
            print(f"   主网 P2PKH: {result['mainnet_p2pkh']}")
            print(f"   测试网 P2PKH: {result['testnet_p2pkh']}")
            print(f"   嵌套隔离见证 (P2SH): {result['p2sh_nested_segwit']}")
            
            print(f"\n💡 说明:")
            print(f"   - P2PKH: 传统支付到公钥哈希地址")
            print(f"   - P2SH: 支付到脚本哈希，支持多重签名和嵌套隔离见证")
            print(f"   - 测试网: 用于测试环境的地址")
            
        elif choice == '2':
            print("\n" + "-" * 40)
            print("比特币地址验证")
            print("-" * 40)
            
            address = input("请输入要验证的比特币地址: ").strip()
            
            if not address:
                print("错误: 地址不能为空")
                continue
                
            is_valid, message = validate_bitcoin_address(address)
            
            if is_valid:
                print(f"\n✅ {message}")
            else:
                print(f"\n❌ {message}")
                
        elif choice == '3':
            print("\n感谢使用，再见！")
            break
            
        else:
            print("\n错误: 无效选项，请重新选择")
        
        # 询问是否继续
        if choice in ['1', '2']:
            continue_choice = input("\n是否继续? (y/n): ").strip().lower()
            if continue_choice not in ['y', 'yes', '是']:
                print("感谢使用，再见！")
                break

if __name__ == "__main__":
    main()