# Kortex

Terminal görünümlü, açık kaynak bir güvenlik tarama aracı.

## Özellikler
- Linux benzeri komut satırı, ilk açılışta kullanıcı adı sorar (`kullanici@kortex:~$`).
- Kod tarama: yaygın güvenlik hatalarını bulur ve `kortex-report.json` dosyası yazar.
- Port tarama ve HTTP güvenlik başlığı denetimi.
- Claude Code ve Codex için `skills/kortex-security` skill'i: ajan raporu okuyup yalnızca listelenen sorunları düzeltir.

## Kurulum
    python -m kortex

Yalnızca standart kütüphane kullanır, ek paket gerekmez. Python 3.10+ gerekir.

## Etik ve yasal kullanım
Port ve web taraması yalnızca sahibi olduğun veya yazılı izin aldığın hedeflerde yapılmalıdır.
Kortex ilk taramada hedefi izin listesine eklemeni ister. Başkalarının sistemlerine izinsiz tarama
yapmak çoğu ülkede suçtur.

## Skill kurulumu (Claude Code / Codex)
`skills/kortex-security/SKILL.md` dosyasını proje içindeki ajan skill klasörüne kopyala ve ajana
"kortex-security skill'ini kullanarak raporu düzelt" de.

## Lisans
MIT (eklemeden önce LICENSE dosyasını ekle).
