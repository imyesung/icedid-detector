import re
import struct
import pefile
import sys
from ..base_analyzer import BaseAnalyzer
class IcedIDAnalyzer(BaseAnalyzer):
    """
    IcedID용 동적 분석/복호화 로직을 담은 Analyzer 클래스 예시.
    """

    def __init__(self):
        super().__init__()

    def extract_encrypted_blob(self, file_path: str) -> bytes:
        """
        1) 파일 전체를 읽어보고,
        2) PE 형식(MZ 시그니처)일 경우 .data 섹션 탐색 후
           처음 나오는 00 00 00 00 이전까지의 데이터(blob)를 추출한다.
        3) 그렇지 않으면 파일 전체 데이터를 반환한다.
        """
        with open(file_path, "rb") as f:
            data = f.read()

        # PE(MZ) 체크
        if data.startswith(b"MZ"):
            try:
                pe = pefile.PE(file_path)
                for section in pe.sections:
                    if b".data" in section.Name:
                        rdata = section.get_data()
                        offset = re.search(b'\x00\x00\x00\x00', rdata).start()
                        return rdata[:offset]
            except Exception as e:
                print(f"[extract_encrypted_blob] 예외 발생: {e}")
                return data

        return data

    def ror32(self, value: int, shift_bits: int) -> int:
        """
        32비트 Rotate Right 연산 함수.
        """
        left = (value >> shift_bits)
        right = (value << (32 - shift_bits))
        return (left | right) & 0xffffffff

    def icedid_decrypt(self, encrypted_data: bytes) -> bytes:
        """
        IcedID가 사용하는 암호화 로직을 적용해
        전체 바이트열(encrypted_data)을 복호화한다.
        마지막 16바이트를 키로 사용하며, 매 바이트마다 key를 업데이트한다.
        """
        max_len = len(encrypted_data)
        decoded = bytearray(encrypted_data)

        # 키 초기화: 암호문 마지막 16바이트에서 추출
        raw_key = encrypted_data[-16:]
        key_list = [struct.unpack('<I', raw_key[i*4:i*4+4])[0] for i in range(4)]

        for count in range(max_len):
            counter = count & 3
            index = ((count & 0xff) + 1) & 3

            # 실제 복호화 연산
            decoded[count] = ((key_list[index] + key_list[counter]) ^ encrypted_data[count]) & 0xff

            # key 업데이트
            key_list[counter] = (self.ror32(key_list[counter], key_list[counter] & 7) + 1) & 0xffffffff
            key_list[index]   = (self.ror32(key_list[index],   key_list[index]   & 7) + 1) & 0xffffffff

        return bytes(decoded)

    def analyze(self, sample_path: str) -> dict:
        """
        1) sample_path의 파일에서 암호화된 Blob 추출
        2) IcedID 복호화 로직 적용
        3) 문자열을 추출해 IcedID 관련 IOC 등을 식별
        4) 분석 결과(예: 문자열 개수, 의심 문자열 등)를 dict 형태로 리턴
        """
        try:
            enc_data = self.extract_encrypted_blob(sample_path)
            dec_data = self.icedid_decrypt(enc_data)

            # 10자 이상 연속된 문자열 패턴 추출
            str_matches = re.findall(rb"[a-zA-Z0-9\.\-]{10,}", dec_data)
            decoded_strings = [s.decode('latin1', errors='ignore') for s in str_matches]

            # IcedID 의심 IOC 식별 (예제)
            suspected_ioc = [s for s in decoded_strings if "icedid" in s.lower()]

            return {
                "total_strings": len(decoded_strings),
                "suspected_ioc": suspected_ioc,
            }
        except Exception as e:
            print(f"[ERROR] 분석 중 오류 발생: {e}")
            return {}

### 🛠 실행 가능하도록 CLI 코드 추가
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python icedid_analyzer.py <파일 경로>")
        sys.exit(1)

    sample_path = sys.argv[1]

    try:
        analyzer = IcedIDAnalyzer()
        result = analyzer.analyze(sample_path)

        print("\n[ 분석 결과 ]")
        print(f"추출된 문자열 개수: {result['total_strings']}")
        if result["suspected_ioc"]:
            print("발견된 IcedID IOC:")
            for ioc in result["suspected_ioc"]:
                print(f"  - {ioc}")
        else:
            print("IcedID 관련 IOC 없음.")

    except Exception as e:
        print(f"[ERROR] 실행 중 오류 발생: {e}")
        sys.exit(1)