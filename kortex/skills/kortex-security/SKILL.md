---
name: kortex-security
description: Kortex güvenlik raporunu okuyup yalnızca raporlanan güvenlik açıklarını düzeltir. Kullanıcı güvenlik taraması, açık kapatma veya kortex-report.json hakkında konuşursa kullan.
---

# Kortex Güvenlik Skill'i

## Amaç
Kortex, kodu tarayıp `kortex-report.json` dosyasına kısa bir rapor yazar. Senin görevin bu raporu okuyup
listelenen sorunları düzeltmek. Tüm projeyi okumana gerek yok.

## Adımlar
1. Rapor yoksa önce çalıştır: `python -m kortex.cli scan-code <proje_klasörü> --json`
2. `kortex-report.json` dosyasını oku. Her bulgu şu alanları içerir: `rule`, `file`, `line`, `severity`, `issue`, `fix`.
3. Bulguları `severity` sırasına göre (high, sonra medium) ele al.
4. Her bulgu için yalnızca ilgili dosyanın ilgili satır çevresini aç. Dosyanın tamamını okuma.
5. `fix` önerisini uygula. Gerekmiyorsa veya emin değilsen değişiklik yapma, kullanıcıya sor.
6. Değişikliklerden sonra testleri çalıştır ve `scan-code` komutunu tekrar çalıştırarak bulgunun kapandığını doğrula.

## Kurallar
- `.env` dosyalarını okuma, değerleri asla yazdırma veya commit etme.
- `hardcoded-secret` bulgusunda anahtarı kodda değiştirmek yetmez: kullanıcıya anahtarın yenilenmesi gerektiğini söyle.
- Raporda olmayan sorunlar için yeni kapsamlı değişiklik yapma.
- Hedef sistemlere (sunucu, site) istek atma. Kortex dışında tarama yapma.
- Her düzeltmeden sonra kısa bir özet ver: dosya, satır, ne değişti.
