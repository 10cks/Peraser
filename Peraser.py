import pefile
import sys

def zero_fill_signatures(pe_file_path, signatures):
    try:
        pe = pefile.PE(pe_file_path)
        
        # 检查是否存在数据段
        data_section = None
        for section in pe.sections:
            if section.Name.decode().strip('\x00') == '.rdata':
                data_section = section
                break
        
        if data_section is None:
            print("没有找到 .rdata 段")
            return False
        
        data_modified = False
        
        # 检查数据段中是否存在指定的签名
        for signature in signatures:
            signature_bytes = signature.encode('utf-8')
            data = data_section.get_data()
            signature_offset = data.find(signature_bytes)
            while signature_offset != -1:
                print(f"在 .rdata 段中发现 {signature} 标识")
                
                # 计算标识在文件中的偏移位置
                file_offset = data_section.PointerToRawData + signature_offset
                
                # 生成一个填充为零的bytes对象，长度与签名相同
                zero_data = bytes(len(signature_bytes))
                
                # 将标识填充为零
                pe.set_bytes_at_offset(file_offset, zero_data)
                data_modified = True
                
                # 继续在剩余的数据中查找签名
                signature_offset = data.find(signature_bytes, signature_offset + len(signature_bytes))
        
        if data_modified:
            # 更新 PE 文件的校验和
            pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
            
            # 保存修改后的 PE 文件
            modified_pe_file_path = pe_file_path[:-4] + '_modified.exe'
            pe.write(filename=modified_pe_file_path)
            print(f"已将所有标识填充为零，并保存为 {modified_pe_file_path}")
            return True
        
        print("未发现指定的标识")
        return False
        
    except pefile.PEFormatError:
        print("无效的 PE 文件格式")
        return False
    except Exception as e:
        print(f"发生错误: {str(e)}")
        return False

def main():
    if len(sys.argv) != 2:
        print("用法: python Peraser.py <pe_file_path>")
    else:
        pe_file_path = sys.argv[1]
        # 将所有需要填充的签名添加到列表中
        signatures = [
            "GCC: (GNU) 9.2-win32 20191008",
            "GCC: (GNU) 9.3-win32 20200320",
            "Mingw-w64",
            "Unknown error",
            "Argument domain error (DOMAIN)",
            "Overflow range error (OVERFLOW)",
            "Partial loss of significance (PLOSS)",
            "Total loss of significance (TLOSS)",
            "The result is too small to be represented (UNDERFLOW)",
            "Argument singularity (SIGN)",
            "_matherr(): %s in %s(%g, %g)  (retval=%g)",
            " runtime failure:",
            "Address %p has no image-section",
            "VirtualQuery failed for %d bytes at address %p",
            "VirtualProtect failed with code 0x%x",
            "Unknown pseudo relocation protocol version %d.",
            "Unknown pseudo relocation bit size %d.",
            ".pdata",
        ]
        zero_fill_signatures(pe_file_path, signatures)

if __name__ == "__main__":
    main()