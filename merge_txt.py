import re
import ssl
import socket
import json
from urllib.parse import parse_qs
from typing import Dict, List, Tuple, Optional
from datetime import datetime


class ProxyValidator:
    """
    Валидирует сертификаты для VLESS и Trojan прокси.
    Пропускает проверку для REALITY протокола.
    Все в одном файле, без дополнительных зависимостей.
    """
    
    VLESS_PATTERN = re.compile(
        r'^vless://([a-f0-9\-]+)@([a-z0-9\-\.]+):(\\d+)/?(.*)$',
        re.IGNORECASE
    )
    
    TROJAN_PATTERN = re.compile(
        r'^trojan://([a-z0-9\-]+)@([a-z0-9\-\.]+):(\\d+)/?(.*)$',
        re.IGNORECASE
    )
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.validation_results = []
    
    def parse_uri_params(self, params_str: str) -> Dict[str, str]:
        """Парсит параметры из query string."""
        if not params_str:
            return {}
        
        result = {}
        params_dict = parse_qs(params_str)
        for key, value in params_dict.items():
            result[key] = value[0] if value else None
        
        return result
    
    def parse_vless_uri(self, uri: str) -> Optional[Dict]:
        """Парсит VLESS URI."""
        match = self.VLESS_PATTERN.match(uri.strip())
        if not match:
            return None
        
        uuid, host, port, params = match.groups()
        return {
            'type': 'vless',
            'uuid': uuid,
            'host': host,
            'port': int(port),
            'params': self.parse_uri_params(params)
        }
    
    def parse_trojan_uri(self, uri: str) -> Optional[Dict]:
        """Парсит Trojan URI."""
        match = self.TROJAN_PATTERN.match(uri.strip())
        if not match:
            return None
        
        password, host, port, params = match.groups()
        return {
            'type': 'trojan',
            'password': password,
            'host': host,
            'port': int(port),
            'params': self.parse_uri_params(params)
        }
    
    def is_reality_protocol(self, proxy_config: Dict) -> bool:
        """Проверяет, использует ли прокси REALITY протокол."""
        params = proxy_config.get('params', {})
        
        # Проверяем REALITY-специфичные параметры
        if params.get('security') == 'reality':
            return True
        
        # Наличие 'pbk' (public key) также указывает на REALITY
        if 'pbk' in params:
            return True
        
        return False
    
    def get_certificate_info(self, host: str, port: int) -> Optional[Dict]:
        """Получает информацию о сертификате хоста через SSL."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'san': cert.get('subjectAltName', [])
                        }
        except ssl.SSLError as e:
            return {'error': f'SSL Error: {str(e)}'}
        except socket.timeout:
            return {'error': 'Connection timeout'}
        except ConnectionRefusedError:
            return {'error': 'Connection refused'}
        except socket.gaierror:
            return {'error': 'Host not found'}
        except Exception as e:
            return {'error': f'Error: {str(e)}'}
    
    def validate_certificate(self, cert_info: Dict) -> Tuple[bool, str]:
        """Валидирует сертификат."""
        if 'error' in cert_info:
            return False, cert_info['error']
        
        if not cert_info.get('subject'):
            return False, "Сертификат не содержит subject информации"
        
        subject = cert_info.get('subject', {})
        issuer = cert_info.get('issuer', {})
        
        # Проверяем самоподписанный сертификат
        if subject == issuer:
            return False, "Сертификат самоподписан"
        
        # Проверяем наличие CN
        if not subject.get('commonName'):
            return False, "Сертификат не содержит Common Name"
        
        return True, "Сертификат валиден"
    
    def validate_proxy(self, proxy_uri: str) -> Dict:
        """Валидирует один прокси."""
        result = {
            'uri': proxy_uri,
            'valid': False,
            'status': 'Unknown',
            'message': '',
            'details': {}
        }
        
        # Парсим URI
        proxy_config = self.parse_vless_uri(proxy_uri)
        if not proxy_config:
            proxy_config = self.parse_trojan_uri(proxy_uri)
        
        if not proxy_config:
            result['status'] = 'Error'
            result['message'] = 'Неподдерживаемый формат URI'
            self.validation_results.append(result)
            return result
        
        result['details']['type'] = proxy_config.get('type')
        result['details']['host'] = proxy_config.get('host')
        result['details']['port'] = proxy_config.get('port')
        
        # Проверяем REALITY
        if self.is_reality_protocol(proxy_config):
            result['valid'] = True
            result['status'] = 'Skipped'
            result['message'] = 'REALITY - проверка TLS не требуется'
            result['details']['uses_reality'] = True
            self.validation_results.append(result)
            return result
        
        result['details']['uses_reality'] = False
        
        # Проверяем сертификат для TLS
        cert_info = self.get_certificate_info(
            proxy_config.get('host'),
            proxy_config.get('port')
        )
        
        result['details']['certificate_info'] = cert_info
        
        is_valid, message = self.validate_certificate(cert_info)
        result['valid'] = is_valid
        result['status'] = 'Valid' if is_valid else 'Invalid'
        result['message'] = message
        
        self.validation_results.append(result)
        return result
    
    def validate_proxies(self, proxies: List[str]) -> List[Dict]:
        """Валидирует список прокси."""
        results = []
        for proxy in proxies:
            results.append(self.validate_proxy(proxy))
        return results
    
    def get_report(self) -> Dict:
        """Генерирует отчет по валидации."""
        total = len(self.validation_results)
        valid = sum(1 for r in self.validation_results if r['valid'])
        invalid = sum(1 for r in self.validation_results 
                     if not r['valid'] and r['status'] != 'Skipped')
        skipped = sum(1 for r in self.validation_results if r['status'] == 'Skipped')
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total': total,
            'valid': valid,
            'invalid': invalid,
            'skipped': skipped,
            'success_rate': f"{(valid/total*100):.1f}%" if total > 0 else "N/A",
            'results': self.validation_results
        }


class ProxyMerger:
    """Объединяет и валидирует прокси из разных источников."""
    
    def __init__(self, validate_certificates: bool = True, timeout: int = 5):
        self.proxies = []
        self.validate_certificates = validate_certificates
        self.validator = ProxyValidator(timeout=timeout) if validate_certificates else None
    
    def add_proxies_from_file(self, filename: str) -> int:
        """Добавляет прокси из файла. Возвращает количество добавленных."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.proxies.append(line)
            return len(self.proxies)
        except FileNotFoundError:
            print(f"Ошибка: файл {filename} не найден")
            return 0
    
    def add_proxies_from_text(self, text: str) -> int:
        """Добавляет прокси из текста."""
        count = 0
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                self.proxies.append(line)
                count += 1
        return count
    
    def is_valid_proxy_uri(self, uri: str) -> bool:
        """Проверяет базовый формат URI."""
        patterns = [
            r'^vless://',
            r'^trojan://',
            r'^vmess://',
            r'^ss://',
            r'^ssr://',
            r'^http://',
            r'^https://',
            r'^socks://'
        ]
        return any(re.match(pattern, uri, re.IGNORECASE) for pattern in patterns)
    
    def filter_valid_proxies(self) -> Tuple[List[str], List[str]]:
        """Фильтрует валидные по формату прокси."""
        valid = []
        invalid = []
        
        for proxy in self.proxies:
            if self.is_valid_proxy_uri(proxy):
                valid.append(proxy)
            else:
                invalid.append(proxy)
        
        return valid, invalid
    
    def validate_and_filter(self) -> List[str]:
        """
        Валидирует прокси по сертификатам.
        Для VLESS/Trojan: проверяет сертификаты, пропускает REALITY.
        """
        valid_proxies, invalid = self.filter_valid_proxies()
        
        if invalid:
            print(f"[!] Найдено {len(invalid)} невалидных по формату прокси")
        
        if not self.validate_certificates or not self.validator:
            return valid_proxies
        
        valid_after_cert_check = []
        
        print(f"[*] Проверка сертификатов для {len(valid_proxies)} прокси...")
        
        for proxy in valid_proxies:
            if proxy.lower().startswith(('vless://', 'trojan://')):
                result = self.validator.validate_proxy(proxy)
                
                if result['valid'] or result['status'] == 'Skipped':
                    valid_after_cert_check.append(proxy)
                else:
                    print(f"    [✗] {proxy[:50]}... - {result['message']}")
            else:
                valid_after_cert_check.append(proxy)
        
        return valid_after_cert_check
    
    def remove_duplicates(self, proxies: List[str]) -> List[str]:
        """Удаляет дубликаты."""
        original_count = len(proxies)
        unique = list(dict.fromkeys(proxies))
        
        if len(unique) < original_count:
            print(f"[*] Удалено {original_count - len(unique)} дублей")
        
        return unique
    
    def merge(self, validate_certs: bool = None) -> List[str]:
        """Объединяет, валидирует и очищает список прокси."""
        if validate_certs is not None:
            self.validate_certificates = validate_certs
            if validate_certs and not self.validator:
                self.validator = ProxyValidator()
        
        print(f"[*] Всего загружено прокси: {len(self.proxies)}")
        
        # Этап 1: Валидируем и фильтруем
        merged = self.validate_and_filter()
        
        # Этап 2: Удаляем дубликаты
        merged = self.remove_duplicates(merged)
        
        print(f"[+] Финальное количество валидных прокси: {len(merged)}\n")
        
        return merged
    
    def save_to_file(self, proxies: List[str], filename: str) -> bool:
        """Сохраняет прокси в файл."""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for proxy in proxies:
                    f.write(proxy + '\n')
            print(f"[+] Сохранено {len(proxies)} прокси в {filename}")
            return True
        except IOError as e:
            print(f"[!] Ошибка при сохранении: {e}")
            return False
    
    def save_validation_report(self, filename: str) -> bool:
        """Сохраняет отчет о валидации в JSON."""
        if not self.validator or not self.validator.validation_results:
            print("[!] Нет результатов валидации для сохранения")
            return False
        
        report = self.validator.get_report()
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"[+] Отчет валидации сохранен в {filename}")
            return True
        except IOError as e:
            print(f"[!] Ошибка при сохранении отчета: {e}")
            return False
    
    def print_summary(self) -> None:
        """Выводит сводку валидации."""
        if not self.validator or not self.validator.validation_results:
            return
        
        report = self.validator.get_report()
        
        print("\n" + "="*70)
        print("ОТЧЕТ О ВАЛИДАЦИИ ПРОКСИ")
        print("="*70)
        print(f"Дата/время: {report['timestamp']}")
        print(f"Всего проверено: {report['total']}")
        print(f"  ✓ Валидных: {report['valid']}")
        print(f"  ✗ Невалидных: {report['invalid']}")
        print(f"  ⊘ Пропущено (REALITY): {report['skipped']}")
        print(f"Процент успеха: {report['success_rate']}")
        print("="*70 + "\n")


def main():
    """Главная функция."""
    print("="*70)
    print("УТИЛИТА ОБЪЕДИНЕНИЯ И ВАЛИДАЦИИ ПРОКСИ")
    print("="*70 + "\n")
    
    # Создаем merger с валидацией сертификатов
    merger = ProxyMerger(validate_certificates=True, timeout=5)
    
    # Загружаем прокси из файла
    print("[*] Загрузка прокси из файла...")
    count = merger.add_proxies_from_file('merged_proxies.txt')
    
    if count == 0:
        print("[!] Не удалось загрузить прокси")
        return
    
    print(f"[+] Загружено {count} прокси\n")
    
    # Объединяем и валидируем (с проверкой сертификатов для VLESS/Trojan)
    merged_proxies = merger.merge()
    
    if merged_proxies:
        # Сохраняем результаты
        merger.save_to_file(merged_proxies, 'merged_proxies.txt')
        merger.save_validation_report('validation_report.json')
        merger.print_summary()
        print("[+] Процесс завершен успешно!")
    else:
        print("[!] Нет валидных прокси после фильтрации")


if __name__ == '__main__':
    main()