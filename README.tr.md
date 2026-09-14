# KARGU-OSINT

**KARGU: Şüpheci OSINT ve Kimlik Doğrulama Orkestratörü.** Adını eski Türk sınır boylarındaki *kargu* gözetleme kulelerinden alır — uzağı izleyen, erken uyarı veren, ateşle haber ileten kuleler. Bu araç bir kişinin dijital izini tarar, doğrular ve eler; kendi izini sızdırmadan.

Kişi-odaklı OSINT otomasyonu. Araç çıktıları ve arayüz **İngilizce**; bu rehber Türkçe (İngilizce sürüm: [README.md](README.md)).
Tarayıcının ihtiyaç duyduğu her şey tek bir klasörün altında (pipx/venv, sudo'suz). Dışarıda bıraktığı
birkaç iz (`~/.local/bin` kısayolları, theHarvester'ın anahtar dosyası, instaloader oturumu, SpiderFoot
Docker imajı) bölüm 8'de listeli.

> **Klasör nerede olursa olsun çalışır.** Script'ler kendi konumlarını `__file__` /
> `readlink -f "$0"` ile bulur; istersen `OSINT_HOME` ile başka bir yer gösterebilirsin.
> Aşağıda `~/osint/…` yazan yerleri "bu klasörün altında" diye oku.
>
> **Klasörü taşıdıysan** üç şeyi yenilemen gerekir, çünkü bunlar mutlak yol gömer:
> ```bash
> # 1) pipx venv'lerindeki ve theHarvester .venv'indeki shebang + .pth kayıtları
> OLD=/eski/yol/osint; NEW="$(pwd)"
> grep -rIl "$OLD" pipx/venvs tools/*/.venv | xargs -r sed -i "s|$OLD|$NEW|g"
> # 2) ~/.local/bin kısayolları
> for c in kargu kargu-new kargu-ui kargu-tor; do ln -sfn "$NEW/$c" ~/.local/bin/$c; done
> # 3) bin/ içindeki bağlantılar göreceli olduğu için kendiliğinden taşınır — kontrol:
> for f in bin/*; do [ -e "$f" ] || echo "KIRIK: $f"; done
> ```
> Bu yapılmazsa hiçbir araç bulunamaz ve tarama **sessizce boş rapor** üretir.

---

## 0) Kurulum

Repoda yalnızca uygulama kodu var; araç ortamları (`pipx/`, `tools/`, `bin/` bağlantıları) klasörün
içine kurulur ve git'e girmez. Taze bir clone'da:

```bash
git clone <repo> osint && cd osint
python3 -m pip install --user -r requirements.txt   # flask, requests, Pillow, PySocks
./install.sh    # pipx + 7 araç + theHarvester + ExifTool + PhoneInfoga — hepsi bu klasörün altına
```

`install.sh` yeniden çalıştırılabilir (kurulu olanı atlar) ve sonunda testleri + her aracı dener. OPSEC
katmanını **kurmaz**, yalnızca hangisinin eksik olduğunu söyler: `tor` ve `proxychains-ng` (`--tor` için),
`mullvad` (raporun tespit edebildiği VPN), `docker` + yerel build (`--deep` için). Bunlar sistem paketleridir
ve senin makinene aittir — bkz. bölüm 16.

## 1) Üç kullanım şekli

| Komut | Ne yapar |
|---|---|
| `kargu-new` | **Soru-cevap sihirbazı.** Adım adım (ad soyad → kullanıcı adları → e-posta → telefon → domain → dosya → referans fotoğraf → not) sorar, doğrular, hedef dosyasını yazar ve taramayı başlatır. |
| `kargu-ui` | **Yerel web arayüzü** — `http://127.0.0.1:8787`. Terminal bu sürece özel erişim token'ı taşıyan bir link (`/?t=…`) basar ve tarayıcıda açar; token'sız arayüz 403 döner, basılan linki kullan. Aynı sorular form olarak; tarama canlı log ile akar, bitince rapora link verir. **Terminali kapatma:** siteyi bu komut sunuyor, Ctrl+C ile durur. Port doluysa otomatik bir sonrakini seçer (`--port N`, `--no-browser`). Tarama başlatma isteği CSRF token'ı ve `Origin`/`Host` kontrolüyle korunur: aynı tarayıcıda açık başka bir sitenin arka planda senin adına tarama başlatmasını engeller. |
| `kargu <hedef.txt>` | Elle hazırladığın hedef dosyasıyla klasik çalıştırma. Rapor txt'nin yanına düşer. |
| `kargu-dash` | **Füzyon paneli** (`http://127.0.0.1:8788`): sürükle-bırak referans fotoğraflı "Yeni tarama" formu, sonra her vaka için tek sayfa — solda kimlik, ortada harita + açık kaynak akışları, sağda resimler / aynı-fotoğraf kümeleri / yüz eşleştirme. `kargu-ui` ile aynı token bağlantısı ve CSRF koruması. Bölüm 17. |
| `kargu-tor start` | `--tor` taramaları için yerel Tor istemcisini başlatır (root gerekmez). `stop` / `status` da var. |

### `kargu-new` nasıl görünür

```
[1/8] Full name
      First and last name of the target. Used to derive candidate usernames.
      e.g. John Doe
      Type "no" (or press Enter) to skip this step.
      > Ayşe Nur Güneş
      · recorded: Ayşe Nur Güneş

[2/8] Usernames / handles
      Nicknames this person commonly uses. Separate several with commas.
      e.g. johndoe, jdoe_92, jd.doe   ·  separate multiple values with commas
      > aysegunes, ayse_92
      · recorded: aysegunes, ayse_92
```

Her adımda **`no` yazarsan (ya da boş Enter)** o alan atlanır. Çoklu alanlarda
değerleri **virgülle** ayırırsın. Geçersiz değer girersen (bozuk e-posta, kısa numara)
script uyarır ve tekrar sorar. Sonunda özet tablo + onay çıkar, sonra tarama başlar.

Seçenekler de sorulur: aday kullanıcı adı türetilsin mi (kaç tane), API kaynakları
kullanılsın mı, Tor üzerinden mi, SpiderFoot derin tarama açılsın mı.

```bash
kargu-new                  # tam sihirbaz
kargu-new --name vaka1     # vaka adını önceden ver
kargu-new --no-run         # sadece hedef dosyasını yaz, tarama yapma
```

## 2) Çıktılar — her tarama = **tek klasör**

```
~/osint/cases/<vaka>_<tarih>/
├── <vaka>.txt          profil + sonunda AUTO-FINDINGS bloğu (bulunan hesaplar, siteler, telefon…)
├── <vaka>.html         okunaklı rapor (tek dosya, avatarlar gömülü)
├── <vaka>.json         makine-okunur dışa aktarım — füzyon panelinin okuduğu dosya
├── images/             yakalanan avatarların ve referans fotoğrafların yüz-kalitesinde kopyaları (--faces için)
├── refs/               panel formundan yüklenen referans fotoğraflar
├── <vaka>.vision.json  panelden yeniden çalıştırılan yüz / CLIP sonuçları (isteğe bağlı)
└── telegram.jsonl      Telegram dinleyicisinin çıktısı, çalıştırırsan (isteğe bağlı)
```

HTML rapor: özet kartları (kaç hesap, **kaçı doğrulandı**, kaçı kararsız, kaçı gerçekten
yok, kaç tanesine buradan erişilemedi — bu dört sayı tablodaki satır sayısını tam olarak
verir), profillerden
toplanan **gerçek ad / bio / açıktaki e-postalar** kutusu, avatarlı ve **filtrelenebilir** hesap
tablosu, açılır listeler, koyu/açık tema. Avatarlar dosyanın içine gömülür — tek dosya kalır. Aç: `xdg-open ~/osint/cases/<vaka>_<tarih>/<vaka>.html`

Doğrulayıcının karar veremediği satırlar (`could not confirm`, `blocked by site`, `unknown`) ana tabloda
değil, siteye göre gruplanmış **katlı bir "Undecided" bloğunda** durur: bunlar kanıt değildir ve tek tek
listelenince gerçek sonuçları gömüyordu. Hiçbir satır kaybolmaz; blok tıklanınca açılır, her handle linklidir.

Ne kadar test yaparsan yap her vaka kendi klasöründe kalır; `data/` ve `reports/` klasörleri
kalktı.

Aynı vakayı tekrar tararsan AUTO-FINDINGS bloğu **üzerine yazılır**, alta ikinci bir blok
eklenmez; yani `.txt` içinde birbiriyle çelişen iki sonuç kümesi oluşmaz. Blok iki uçtan
sınırlıdır (`# ==== AUTO-FINDINGS …` / `# ==== END AUTO-FINDINGS …`), dolayısıyla
**bloğun altına kendi notlarını yazabilirsin** — sonraki tarama onları korur. (Eskiden
başlıktan dosya sonuna kadar her şey silindiği için elle eklenen notlar kayboluyordu.)

`kargu <hedef.txt>` ile elle çalıştırırsan rapor **o txt'nin yanına** yazılır.

## 3) Boru hattı (mantık sırası)

Gerçek çalışma sırası: Identity → E-mail → Social → **Verify** → Instagram → Domain →
**Correlation** → Phone → Metadata → `--deep`. (Doğrulama listede 2. sırada anlatılıyor çünkü
mantıken oraya ait; kodda e-posta ve social'dan sonra çalışır. Arşiv kontrolü — bölüm 14 —
doğrulamanın *içinde* olduğu için `--no-verify` onu da kapatır.)

1. **Identity** — her username → `sherlock` + `maigret` (hesap keşfi)
2. **Verify + enrich** — bulunan **her hesap URL'i gerçekten açılır** (8 paralel istek):
   - sayfa yükleniyor mu, kullanıcı adı gerçekten orada mı → **false-positive'ler elenir**
   - `<title>` / `og:description` çekilir → **gerçek ad, bio**
   - **Avatar:** `og:image` çoğu sitede kişinin fotoğrafı DEĞİL, sitenin varsayılan paylaşım
     kartıdır (Pinterest `default_open_graph`, Telegram logosu, chess.com 1200x630 kartı).
     Bu yüzden aday görseller şekle ve URL'ye göre eleniyor: avatar kare-benzeridir (en/boy
     0.75–1.34), URL'sinde `default|logo|share|opengraph` geçen görsel atılır. Bulunamazsa
     avatar gösterilmez — yanlış göstermektense boş bırakılır.
   - **Aynı fotoğraf eşleştirmesi — iki kademeli.** Avatarların hem sha256'sı hem algısal
     hash'i (dHash) çıkarılır ve rapor iddiayı kanıtın gücüne göre ayırır:
     · **strong** — görsel dosyaları **bayt bayt aynı**. Yanlış eşleşme riski sıfırdır.
     · **possible** — aynı fotoğrafın başka boyutta kodlanmış hâli (dHash farkı ≤ 6/64).
       Gerçek bir kanıttır ama gözle teyit istenir.
     Sadece **farklı platformları** kapsayan gruplar kanıt sayılır (github.com + gist.github.com
     aynı hesabın iki kaydıdır, kanıt değil). **Düz/varsayılan avatarlar tamamen elenir:**
     gri siluet ya da tek renk varsayılan görsel neredeyse hep-sıfır veya hep-bir bit
     örüntüsü verir ve internetteki her varsayılan avatarla eşleşir — iki yabancının aynı
     fotoğrafı taşıdığı tek gerçek senaryo tam olarak budur.
   - profilde açıkta duran e-postalar toplanır — ama yalnızca `<title>` ve `og:description`
     içinden (~600 karakter), sayfa gövdesi taranmaz; bu kutunun çoğu zaman boş olması normal
   - Durumlar: `verified` (açıldı ve sayfanın kendi içeriği bu hesaptan söz ediyor) ·
     `does not exist` (aracın uydurması) · `could not confirm` (JS ile render ediliyor,
     onay/bot duvarı çıktı ya da sayfada hiçbir kanıt yok — elle bak) ·
     `blocked by site` (401/403/429) · `unknown` (okunamayan başka bir HTTP durumu) ·
     `unreachable from here` (TLS/DNS seviyesinde patladı)
   - **`verified` için kanıt şart.** Kullanıcı adının **adreste** geçmesi kanıt sayılmaz:
     o URL'yi zaten sherlock/maigret kullanıcı adından **kendisi üretmiştir**, yani her hit
     için doğrudur. Kanıt sayfanın **kendi görünür metninden** ya da **başlığından** gelmek
     zorunda. Arama `<script>`/`<style>` ve tüm etiket öznitelikleri atıldıktan sonra
     yapılır — handle'ın yalnızca bir `href` içinde geçmesi de kanıt değildir, çünkü orası
     yine bizim sorduğumuz adresin kendisidir. Ayrıca eşleşme **kelime sınırıyla** aranır:
     `gune`, yalnızca `aysegunes` içinde geçtiği için sayılmaz. 6+ karakterli handle'larda ayraç-toleranslı
     okuma da kabul edilir ("Ayşe Güneş", @aysegunes için sayılır); 4 karakterin altındaki handle'lar hiç aranmaz.
   - **Onay/bot duvarı ayrımı:** sayfa 200 dönüp de gelen şey Google'ın "Before you continue"
     ekranı ya da Cloudflare kontrolü ise, başlık kontrolü **gövde kanıtından önce** çalışır
     ve hesap `could not confirm` olup arşiv kontrolüne düşer. (Onay ekranı hedef URL'yi
     kendi içinde tekrarladığı için, bu kontrol sırada aşağıda olduğu sürece devre dışı
     kalıyordu: eski bir test vakasındaki dört YouTube satırı, içeriği yalnızca onay
     ekranı olmasına rağmen bu yüzden `verified` işaretlenmişti.)
   - **Gövdesi okunamayan sayfa `verified` olmaz.** Yanıt HTML değilse, okuma hata verirse
     ya da 4 MB sınırı aşılırsa hesap `could not confirm` olur ve nedeni not olarak yazılır.
   - **Önemli:** `unreachable` false-positive DEĞİLDİR. Türkiye'den taradığında Xvideos, Wattpad,
     Pastebin, Polymarket gibi engelli sitelere istek SSLError ile düşüyor — hesap yok demek değil,
     "buradan bakılamadı" demek. Rapor bunu ayrı sayar ve `--tor` ile tekrar çalıştırmanı söyler.
3. **E-mail** — `holehe` (kayıtlı siteler) + `h8mail` (sızıntı) + **gravatar** (profil/gerçek ad/bağlı hesaplar) + HIBP (anahtar varsa)
4. **Social** — `socialscan` (kullanıcı adı/e-posta müsaitlik)
5. **Correlation** — bulunan yeni e-postaları tekrar işler (`--depth N`).
   **Kapsam sınırlı:** yalnızca hedefe *kasıtlı olarak bağlanabilen* adresler takip edilir —
   gravatar'ın döndürdüğü hesaplar, hedefin kendi doğrulanmış profilinde **yayınladığı**
   adresler, ve theHarvester/Hunter'ın **sorgulanan alan adına ait** bulduğu adresler.
   Bio'larda veya whois metninde rastlanan üçüncü şahıs adresleri **takip edilmez**:
   eskiden ediliyordu, yani hedefin bio'sunda geçen bir tanıdığının adresi seni farkında
   olmadan o kişiyi taramaya sokuyordu. Eski davranış `--follow-any-email` ile geri gelir.
   Rapor, takip edilen her adresin **nereden geldiğini** yazar.
6. **Domain** — `theHarvester` + **crt.sh** (sertifika şeffaflığı, crt.sh çökerse otomatik **certspotter**) + **VirusTotal** + **Chaos** + **Hunter.io** + `dnstwist`
7. **Phone** — **numverify** (ülke/operatör/hat tipi) + `phoneinfoga` (Google-dork ayak izi, burner/SMS-site kontrolü)
8. **Metadata** — `exiftool` (EXIF/GPS; GPS varsa rapora harita linki düşer)
9. `--deep` → SpiderFoot

## 4) API anahtarları

Anahtarlar `~/osint/config/.env` içinde (chmod 600, `.gitignore`'da — **push edilmez**).
Şablon: `config/.env.example`. Boş bırakılan anahtar o kaynağı kapatır, tarama yine çalışır.

| Kaynak | Durum | Ne katıyor |
|---|---|---|
| **numverify** | ✅ çalışıyor | Numaranın geçerliliği, ülke, hat tipi (mobile/landline), operatör. Ücretsiz planda operatör alanı çoğu TR numarasında boş döner, hat tipi gelir. |
| **VirusTotal** | ✅ çalışıyor | Domain itibarı, DNS kayıtları, alt alan adları, geçmiş IP'ler, whois, registrar |
| **Chaos** | ✅ çalışıyor | Alt alan adı veri seti (yalnızca herkese açık bug-bounty kapsamları). *Eskiden burada "401, yetkisiz" yazıyordu; anahtar artık çalışıyor ve `theHarvester`'ın `projectdiscovery` kaynağı da tekrar açıldı.* |
| **Hunter.io** | ⭕ anahtar yok | Kurumsal domainlerdeki çalışan e-postaları + e-posta doğrulama. Aşağıya bak. |
| **HIBP** | ⭕ anahtar yok | E-posta başına sızıntı listesi. Ücretli (~4$/ay), `haveibeenpwned.com/API/Key`. |

Anahtar eklemek: `nano ~/osint/config/.env` → satırı doldur → kaydet. Yeniden kurulum gerekmez.
Not: theHarvester'ın kendi anahtar dosyası ayrıca `~/.theHarvester/api-keys.yaml`'dadır (VT + PD orada da duruyor).

### Hunter.io "work mail" nasıl alınır

Hunter ücretsiz planda (ayda 25 arama) **gmail/outlook/yahoo gibi ücretsiz sağlayıcıları reddediyor**;
bir alan adına ait e-posta istiyor. En temiz ve ucuz yol kendi alan adını almak:

1. **Ucuz bir domain al** — Porkbun / Namecheap / Cloudflare Registrar (`.xyz`, `.site` gibi uzantılar ilk yıl ~1-3 $).
2. **Cloudflare Email Routing'i aç** (ücretsiz): domaini Cloudflare'e ekle → *Email* → *Email Routing* → *Create address*
   → `sen@senindomain.com` adresini **gmail adresine yönlendir**, hedef adresi doğrula.
3. **Hunter.io'ya bu adresle kaydol.** Doğrulama maili gmail'ine düşer, linke tıklarsın. Bitti.
   (Mail göndermen gerekmiyor, sadece alman yeterli.)
4. Anahtarı `Dashboard → API` bölümünden kopyala → `config/.env` içindeki `HUNTER_API_KEY=` satırına yapıştır.

Alternatifler: üniversite (`.edu`) veya iş adresin varsa doğrudan kabul edilir.
**Gerçekten gerekli mi?** Hunter kurumsal domainler için bir araçtır (`sirket.com` çalışan e-postaları).
Hedef gmail kullanan bir birey ise Hunter neredeyse hiçbir şey katmaz — bu yüzden opsiyonel bırakıldı.
Şirket domaini araştıracaksan çok işe yarar.

## 5) Bayraklar

| Bayrak | Ne yapar |
|---|---|
| `--tor` | Tor üzerinden çalıştırır — **önce `kargu-tor start`**. Tor gerçekten çalışmıyorsa tarama başlamaz (aşağıya bak). |
| `--deep` | SpiderFoot derin taraması (yavaş) |
| `--no-api` | API anahtarı isteyen kaynakları atla (numverify, VirusTotal, Chaos, Hunter.io, HIBP). Geri kalan her şey — gravatar, crt.sh, hesap doğrulama ve avatarlar, arşiv kontrolü, çıkış adresi sorgusu — ağa çıkmaya devam eder |
| `--max-users N` | isimden/e-postadan türetilecek azami aday sayısı (varsayılan 3) |
| `--no-derive` | aday üretme, sadece verdiğin username'leri kullan |
| `--no-verify` | bulunan hesap URL'lerini açıp doğrulama (hızlı ama çok gürültülü) |
| `--no-avatars` | profil fotoğraflarını çekme. **Dikkat:** sadece görsel değil — aynı-fotoğraf eşleştirmesini (bölüm 3'teki `strong` / `possible` kademeleri) ve ters görsel arama linklerini de kapatır |
| `--no-instagram` | instaloader profil adımını atla |
| `-i, --image YOL\|URL` | kişinin referans fotoğrafı (tekrarlanabilir; hedef dosyadaki `image:` ile aynı). Yakalanan her profil resmiyle hash üzerinden karşılaştırılır, ters görsel arama bağlantıları üretilir |
| `--faces` | referans fotoğraflar ile yakalanan resimler arasında yerel InsightFace modeliyle yüz karşılaştırması (**biyometrik işleme — isteğe bağlı, `dashboard/install-ml.sh` gerekir**, bölüm 17) |
| `--deepface` | `--faces` ile bulunan her eşleşmeyi DeepFace ile (Facenet512 + VGG-Face) yeniden denetler. DeepFace'in kabul etmediği eşleşme **disputed** işaretlenir ve fotoğrafına `DEEPFACE NOT CONFIRMED` damgası basılır |
| `--clip` | referans fotoğraflar ile yakalanan resimler arasında CLIP görsel benzerliği (yerel, aynı venv) |
| `--face-threshold X` | bir yüz çiftinin eşleşme sayılması için gereken kosinüs benzerliği (varsayılan 0.5; ≥ 0.65 güçlü gösterilir) |
| `--no-lockdown` | tarama süresince Mullvad lockdown modunu açma |
| `--verify-workers N` | doğrulamadaki paralel istek sayısı (varsayılan 8) |
| `--depth N` | korelasyon döngü derinliği. Doğrulama ve domain aşamalarından **sonra** çalışır, yani o aşamaların bulduğu yeni e-postaları da takip eder |
| `--follow-any-email` | korelasyonun **kapsamını genişletir**: sonuçların içinde geçen her e-posta adresini takip eder (profil bio'ları, whois metni dahil). Varsayılan olarak **kapalı** — bkz. aşağıdaki kutu |

Ortam değişkenleri (bayrak karşılığı yok): `OSINT_PYTHON` (kullanılacak yorumlayıcı),
`OSINT_DEFAULT_CC` (baştaki `0` yerine konacak ülke kodu, varsayılan `90`),
`OSINT_TOR_PORT` (`kargu-tor` için), `OSINT_UI_PORT`.

**Telefon biçimi:** `0532 …` gibi ulusal yazım otomatik olarak `+90532…`'ye çevrilir.
(Eskiden `+0532…` üretiliyordu — E.164'te 0 diye bir ülke kodu yok, o yüzden rapor numarayı
"geçersiz" diye işaretliyordu.)

## 6) Hedef dosyası formatı (elle yazmak istersen)

`anahtar: değer` — aynı anahtar birden çok kez yazılabilir, bilmiyorsan satırı sil:
```
name: John Doe
username: johndoe
email: john@example.com
phone: +90 5xx xxx xx xx
domain: example.com
file: /home/user/Pictures/photo.jpg
image: /home/user/Pictures/portre.jpg
notes: serbest not
```

Şablon: `target-example.txt` (kopyala, doldur, `kargu dosya.txt`).

## 7) Kurulu araçlar

`~/osint/bin`: maigret · sherlock · holehe · socialscan · dnstwist · h8mail · theHarvester ·
exiftool · phoneinfoga · instaloader

**SpiderFoot (`--deep`) Docker imajından çalışır** (`bin/sf` bir `docker run --network host` çağrısıdır).
İmaj yoksa shim mesajla çıkar, konsol `SpiderFoot did not run` uyarır ve rapora `did not run` bölümü
düşer — sessizce boş üretmez. Rapor SpiderFoot'un ham çıktısının yalnızca sonunu (~4000 karakter) saklar;
hesap/e-posta tablolarına hiçbir şey ayrıştırılmaz. Docker Hub'daki `smicallef/spiderfoot` imajı artık
yok; yerel olarak build et (`install.sh` de aynı komutları basar):

```bash
git clone https://github.com/smicallef/spiderfoot tools/spiderfoot && chmod -R a+rX tools/spiderfoot
docker build --network=host -t smicallef/spiderfoot tools/spiderfoot
```

**h8mail veri kaynağı yok:** `config/h8mail_config.ini` baştan sona yorum satırı, o yüzden
"Breach records: 0" ölçülmüş bir sonuç değil. Anlamlı olması için o dosyaya bir anahtar
(ör. `hibp`) girip satırı yorumdan çıkarman gerekir — script dosyayı artık h8mail'e `-c` ile
**geçiriyor** (eskiden geçirmiyordu, yani anahtarı doldursan da hiçbir şey değişmiyordu).

Kaynak tanımlı değilken rapor artık "0" yazmıyor; **`not checked`** rozetiyle bunun
ölçülmemiş bir soru olduğunu söylüyor. Bir anahtar girdiğinde rapor hangi kaynakların
sorgulandığını da listeler.

## 8) Geri alma (iz bırakmadan)

```bash
# bu klasörün içinden çalıştır
rm -rf "$(pwd)" ~/.local/bin/kargu ~/.local/bin/kargu-new ~/.local/bin/kargu-ui ~/.local/bin/kargu-tor
rm -rf ~/.theHarvester ~/.config/instaloader ~/.local/share/maigret
docker image rm smicallef/spiderfoot   # --deep için build ettiysen
```

İlk satır klasörün tamamını (pipx home'u dahil) siler. İkinci satır klasörün **dışında**
kalan izleri temizler — theHarvester'ın kendi anahtar dosyası orada durur.

Sadece tarama sonuçlarını silmek için: `rm -rf cases/`

## 9) Yasal/etik
Araçlar kamuya açık kaynakları sorgular; yine de hız-limiti/engel yiyebilirsin, `--tor` yardımcı olur.


## 10) Tor — ne kapsıyor, ne kapsamıyor

Önce başlat, sonra tara:

```bash
kargu-tor start                 # ~/osint/.tor altında kendi kullanıcınla çalışır, root gerekmez
kargu cases/vaka/vaka.txt --tor
kargu-tor stop                  # işin bitince
```

`--tor` verdiğinde script Tor'u **doğruluyor**: SOCKS portu dinliyor mu, PySocks var mı ve
`check.torproject.org` gerçekten "IsTor" diyor mu. Biri bile eksikse **taramayı başlatmıyor** —
anonim sandığın ama olmayan bir tarama, hiç Tor'suz taramadan kötüdür.

**Kapsam dürüstlüğü:** Tor iki ayrı yolu etkiler ve ikisi ayrı kurulum ister.

| Trafik | Tor'a giriyor mu |
|---|---|
| Bu programın kendi istekleri (hesap doğrulama, avatar, VT/numverify/crt.sh) | ✅ `socks5h://127.0.0.1:9050` |
| sherlock, maigret, holehe, socialscan (Python, TCP) | ⚠️ yalnızca **proxychains kuruluysa** |
| **phoneinfoga** | ❌ **hiçbir zaman** — aşağıya bak |
| **dnstwist / theHarvester'ın DNS sorguları** | ❌ **hiçbir zaman** — aşağıya bak |
| **`--deep` (SpiderFoot, docker)** | ❌ **hiçbir zaman** — aşağıya bak |

### proxychains'in yapısal olarak kapsayamadığı üç yol

Bunlar eksik kurulum değil, proxychains'in çalışma biçiminin sınırı. Ölçüldü, düzeltilemez;
o yüzden burada yazıyor:

1. **phoneinfoga statik derlenmiş bir Go ikilisi.** (`file bin/phoneinfoga` → *statically linked*.)
   proxychains `LD_PRELOAD` ile libc'nin `connect()` çağrısını değiştirir; statik ikili libc
   kullanmaz, sistem çağrısını doğrudan yapar. Yani `--tor` verilse bile phoneinfoga'nın
   trafiği **doğrudan senin bağlantından** çıkar.
2. **DNS, TCP değil UDP.** `dnstwist` çözümlemeyi `dnspython` ile, `theHarvester` ise
   `aiodns`/`pycares` ile kendisi yapıyor. proxychains TCP bağlantılarını sarar; bu UDP
   sorguları onun dışında kalır. Pratik sonucu: `dnstwist` yüzlerce benzer-domain varyasyonunu
   **yerel DNS çözücüne** (dolayısıyla ISP'ne) sorar.
3. **`--deep` docker ile çalışır.** `bin/sf` bir `docker run` çağrısıdır; docker *istemcisini*
   proxychains ile sarmak *konteynerin* trafiğini yönlendirmez.

**Gerçekten anonim tarama gerekiyorsa** tek güvenilir yol bunları sistem seviyesinde
yönlendirmektir: Mullvad'ı açmak (bkz. bölüm 13) tüm bu yolları da kapsar, çünkü yönlendirme
uygulama katmanında değil ağ katmanında yapılır.

proxychains kurulu (`proxychains-ng`). Script **kendi config'ini** kullanıyor
(`~/osint/.tor/proxychains.conf`, `socks5 127.0.0.1 9050`) çünkü Fedora'nın varsayılan
`/etc/proxychains.conf` dosyası `socks4` yazıyor; socks4'te hostname desteği olmadığı için
DNS'in Tor üzerinden çözülmesi socks5 kadar temiz değil. Doğrulandı:

```
proxychains'siz : 203.0.113.42   Türkiye   Turk Telekom
proxychains ile : 198.51.100.7 Germany   (Tor cikis dugumu)
```

### Çıkış adresi kontrolü — tarama başlamadan

Script artık **her taramanın başında** gerçekten hangi adresten çıktığını ölçüyor
(`am.i.mullvad.net`) ve varsayım yapmıyor:

```
[EXIT] direct · 203.0.113.42 (Turk Telekom, Türkiye)
        Mullvad is installed but disconnected — this scan is attributable to your own
        connection. `mullvad connect` first, or use --tor.
```

Tor veya Mullvad açıksa bunu `[EXIT] Tor · ...` / `[EXIT] Mullvad VPN · ...` diye yazıyor ve
aynı bilgi raporun "Your own footprint" bölümüne düşüyor. Yani rapor "kendi IP'nden" diye
tahmin etmiyor, ölçüyor.

**Neye yarıyor:** Türkiye'den taramada `unreachable from here` çıkan hesaplar Tor üzerinden
çözülüyor. Test ettiğimizde 4 hesaptan 3'ü **404** çıktı — yani ISP engeli, aracın ürettiği
false-positive'leri gizliyormuş. Tor olmadan bunları "belki vardır" diye listede tutuyorduk.

## 11) Instagram (Osintgram yerine instaloader)

`Datalux/Osintgram` incelendi: **zararlı kod yok** (VirusTotal: repo URL ve tüm bağımlılıklar
0 malicious; kaynakta `eval/exec/base64/pickle/subprocess` yok; dışarı sadece instagram.com ve
hikerapi.com). Ama entegre **edilmedi**, çünkü Instagram kullanıcı adı+parolanı düz metin
`.ini` dosyasına yazmanı istiyor, `instagram-private-api` 2019'dan beri güncellenmemiş ve
bakımlı yolu ücretli üçüncü taraf (`hikerapi`) üzerinden geçiyor.

Onun yerine **fikri** alındı: bakımlı `instaloader` ile tek bir profil zenginleştirme adımı —
`full_name`, bio, `external_url`, takipçi/takip, gizli/doğrulanmış, işletme kategorisi ve
**gerçek profil fotoğrafı** (bu, aynı-fotoğraf eşleştirmesine Instagram'ı da dahil eder).

**Durum:** Instagram anonim isteklere (Tor üzerinden bile) **429** dönüyor. Adım kurulu ve
hazır; çalışması için bir kereye mahsus oturum dosyası gerekiyor:

```bash
~/osint/pipx/venvs/instaloader/bin/instaloader --login=<KULLAN-AT-HESAP>
```

**Ana Instagram hesabını kullanma** — otomatik erişim hesap kilitlenmesine yol açabilir.
Oturum dosyası `~/.config/instaloader/session-*` altına düşer, script onu kendiliğinden bulur.
Oturum yoksa adım `skipped` deyip nedenini yazar, tarama normal devam eder. Kapatmak: `--no-instagram`


## 12) Küratörlü pivotlar + OPSEC defteri (OSINT Framework)

`lockfale/OSINT-Framework` bir tarama aracı değil, **1169 kaynaklık küratörlü bir veri seti**
(MIT). Değerli tarafı şu: her kayıtta `opsec: passive|active` ve `opsecNote` alanı var — yani
o kaynağı kullanmanın hedefin loglarında iz bırakıp bırakmadığı yazıyor.

Veri seti `~/osint/resources/arf.json` altına kopyalandı (kaynak/lisans: `resources/SOURCE.md`).
Yalnızca **veri** kullanılıyor; deponun JavaScript/Python kodu çalıştırılmıyor.

### Raporda ne oluyor

**8 · Where to look next** — girdiğin her varlık için (kullanıcı adı, e-posta, domain, telefon,
ad) iki liste:
- **Ready to click:** değeri önceden doldurulmuş linkler (Google tam eşleşme araması, GitHub
  public events — commit e-postaları oradan sızar, ProtonMail anahtar sorgusu, crt.sh, Wayback)
- **Curated:** veri setinden gelen canlı kaynaklar; her biri `passive`/`active` rozeti, ücret
  bilgisi, kayıt gerekip gerekmediği ve OPSEC notuyla

**Önemli:** bu linklerin hiçbiri **çekilmiyor**. Sen tıklayana kadar makineden istek çıkmıyor.
Bu yüzden bulgulara **tek bir false positive bile eklemiyorlar** — otomatik iddia üretmiyorlar,
sadece nereye bakacağını söylüyorlar.

**Ters görsel arama:** yakalanan her gerçek avatar için Google Lens / Yandex / Bing / TinEye
linkleri üretiliyor. Bu, boru hattının daha önce hiç yapamadığı bir pivot.

### 9 · Your own footprint — kendi izin

Rapor artık **senin** ne kadar iz bıraktığını da yazıyor:

| Satır | Ne anlama geliyor |
|---|---|
| How this scan left your machine | ölçülen, varsayılan değil: `direct` (aşağıdaki her istek senin bağlantına atfedilir), `Tor` ya da `Mullvad VPN`, çıkış IP'siyle |
| Exit at the end of the scan | çıkış son aşamadan sonra yeniden ölçülür — `CHANGED`, taramanın bir kısmının farklı (muhtemelen senin) bağlantıdan çıktığı anlamına gelir |
| Mullvad kill-switch | tarama boyunca açık (başta açılır, çıkışta — Ctrl+C dahil — eski değerine döner); `--no-lockdown` dokunmaz |
| Target platforms contacted directly | doğrulama aşamasının kaç siteye kaç istek attığı + host listesi |
| Third parties told about the target | VirusTotal/numverify gibi servisler hangi kimlik bilgisini gördü (senin API anahtarına bağlı olarak) |
| Tools that contacted platforms | sherlock/maigret kullanıcı adı başına yüzlerce siteyi yokluyor; bu trafik sayıma dahil değil ve proxychains kurulu değilse Tor'dan geçmiyor |

Yani "OSINT aracı çalıştırdım" ile "40 profili ev IP'mden ziyaret ettim" cümlesi, o siteler
açısından aynı şey — rapor bunu artık gizlemiyor.


## 13) Çıkış yolu seçimi: Tor mu, Mullvad mı?

Üçünü de aynı hesaplarda ölçtük. Sonuç net: **false-positive temizliği için Mullvad, Tor'dan iyi.**

| Hesap | Doğrudan (Türk Telekom) | Tor | Mullvad (Bükreş) |
|---|---|---|---|
| Wattpad | unreachable (SSLError) | 404 | **404** |
| Xvideos | unreachable (SSLError) | 404 | **404** |
| Polymarket | unreachable (SSLError) | 404 | **404** |
| Pastebin | unreachable (SSLError) | 403 (Tor engelli) | **404** |
| archive.org / Wayback | ConnectTimeout | 403 (Tor engelli) | **çalışıyor** |
| Instagram (anonim) | 429 | 429 | **429** |

Sebep: siteler Tor çıkış düğümlerini engelliyor, Mullvad'ı engellemiyor. Yani `--tor` kimliğini
daha iyi gizler ama daha çok kapı yüzüne kapanır; Mullvad hem ISP engelini aşar hem de siteler
tarafından normal bir kullanıcı gibi görülür.

**En hızlı lokasyon** ölçülerek seçildi (Türkiye'den ping): Bükreş 42 ms · Milano 56 ms ·
Viyana 58 ms · Atina 59 ms · Budapeşte 61 ms · Berlin 72 ms · Sofya 78 ms.

```bash
mullvad relay set location ro buh && mullvad connect
mullvad disconnect        # işin bitince
```

**Instagram:** üç yoldan da 429 dönüyor. Yani anonim erişim gerçekten kapalı; instaloader adımı
için kullan-at hesapla bir kereye mahsus oturum şart (bkz. bölüm 11).

## 14) Arşiv kontrolü — sıfır maliyetli varlık doğrulama

Doğrulama aşamasının karar veremediği hesaplar (`could not confirm`, `unknown`, `blocked`,
`unreachable`) için Internet Archive'a soruluyor: bu profil sayfası hiç kaydedilmiş mi?

**OPSEC açısından bedava:** soru archive.org'a gidiyor, hedefin sitesine **hiç dokunulmuyor**.

**Kasıtlı olarak asimetrik:** 200 dönen bir snapshot varsa sayfa gerçekten vardı → hesap
`archived <tarih>` rozetiyle işaretlenir ve arşiv linki verilir. Kayıt yoksa **hiçbir şey ifade
etmez** (küçük profiller çoğunlukla arşivlenmez), o yüzden bir hesabı asla "yok" diye
işaretlemiyor — sadece yukarı yönlü karar veriyor. Böylece yeni false-positive üretmiyor.

Bazı siteler (ör. Wattpad) arşivden hariç tutulmuş; o durumda "archive.org will not answer for
this domain" yazıyor. archive.org Türkiye'den doğrudan erişilemiyor — bu kontrol **VPN
gerektiriyor** (Tor'dan da 403 alıyor).

## 15) Testler

Doğrulama karar zinciri, ad çıkarımı, fotoğraf gruplaması ve AUTO-FINDINGS yeniden yazımı
için çevrimdışı regresyon testleri var. Ağ, API anahtarı ya da hedef gerekmez — HTTP katmanı
sabit örneklerle değiştirilir:

```bash
/usr/bin/python3 tests/test_verify.py      # ya da: /usr/bin/python3 -m unittest discover tests
```

Sistem yorumlayıcısını kullan (launcher'ların sabitlediği, `OSINT_PYTHON`): bir pipx venv'inin
`python3`'ünde Pillow yoktur ve bir avatar testi hata verir.

Testlerdeki her vaka, gerçekten yayına çıkmış bir hatayı temsil ediyor: onay ekranının
`verified` sayılması, handle'ın yalnızca bir `href` içinde geçmesinin kanıt sanılması,
kısa handle'ın uzun kelimenin içinde eşleşmesi, kişinin kendi bio'sundaki "not found"
esprisinin hesabı öldürmesi, gövdesi okunamayan sayfanın doğrulanmış sayılması, gerçek
adın handle'a benzediği için atılması, iki yabancının paylaştığı varsayılan avatarın
"aynı kişi" kanıtı diye sunulması ve bloğun altına yazılan operatör notlarının silinmesi.

## 16) Kodla gelen ve senin olan

Repoyu klonlayan herkes şunları aynen alır: çıkış tespiti (başta ve sonda ölçülür, değişirse kırmızı uyarı),
Mullvad kill-switch tespiti, `--tor` fail-closed kapısı, OPSEC defteri, SSRF kapısı (özel IP'lere avatar
çekilmez), rapordaki `href`/`img` şema kontrolü, hedef dosyası sertleştirmesi (`$VAR` açılmaz, `-` ile
başlayan değer alınmaz), anahtar redaksiyonu, UI erişim token'ı, arşiv kontrolünün hedefe dokunmaması,
pivot linklerinin hiç çekilmemesi.

Araç şunları **kurmaz, yalnızca görür ve söyler**: Mullvad (abonelik, `mullvad connect`,
lockdown'u tarama kendisi açar ve çıkışta eski hâline döndürür, `--no-lockdown` ile kapatılır), Tor + proxychains-ng, API anahtarların (`config/.env`), SpiderFoot imajı,
DNS ayarların. Mullvad'sız çalıştıran biri raporda `direct · <kendi IP'si>` görür ve her isteğin kendi
bağlantısına atfedildiğini okur — araç onun yerine VPN açmaz. Varsayılan ülke kodu `OSINT_DEFAULT_CC=90`
(Türkiye); başka ülkedeysen ortam değişkeniyle değiştir.

## 17) Füzyon paneli, referans fotoğraflar ve yerel görüntü analizi

`kargu-dash` yerel bir panel açar (yalnız loopback, yazdırılan bağlantıda sürece özel token, `KARGU_DASH_PORT`):

- **Yeni tarama** (`/new`): sihirbazla aynı alanlar + kişinin **referans fotoğrafları** için sürükle-bırak
  alanı (en fazla 8 dosya, 15 MB; her yükleme gerçekten görsel olarak çözülmek zorunda). Fotoğraflar vaka
  klasörüne `refs/` altında kaydedilir, hedef dosyaya `image:` satırları olarak yazılır ve tarama canlı
  log ile arka planda başlar. Başlatma isteği CSRF token'ı ve `Origin`/`Host` denetimi taşır.
- **Vaka sayfası** (`/case/<klasör>`), üç panel:
  - *Kimlik*: özet kartlar, avatarlı doğrulanmış hesaplar, e-posta kayıtları, senin çıkış rotan.
  - *Bağlam*: OpenStreetMap ve NASA GIBS (MODIS gerçek renk, 250 m — arazi, asla insan) katmanlı Leaflet
    haritada EXIF GPS iğneleri; GDELT haber araması (ücretsiz, anahtarsız, 5 saniyede bir sorgu — özel
    kişi nadiren çıkar, kurum/alan adı çıkar); Telegram araması ve dinleyici isabetleri; ilk iğnenin
    çevresi için Sentinel-2 hızlı görünümleri (anahtarlar için bölüm 18).
  - *Görsel*: referans fotoğrafların ve eşleştikleri hesaplar, yakalanan profil resimleri ve
    aynı-fotoğraf kümeleri, yerel görüntü analizi bloğu.

### Referans fotoğraflar ve eşleşme dereceleri

Her referans fotoğraf (`image:` / `-i`) avatarlar gibi hash'lenir (SHA-256, dHash, pHash, merkez
kırpımlar) ve doğrulanmış her hesabın resmiyle karşılaştırılır. Rapor ve panel her eşleşmeyi etiketler:

| Etiket | Anlamı |
|---|---|
| `strong` | bayt-bayt aynı dosya |
| `possible` | algısal hash toleransta — aynı resim, belki yeniden kodlanmış ya da kırpılmış |
| `face 0.xx` | InsightFace gömme kosinüsü ≥ eşik (`--faces`); ≥ 0.65 yeşil gösterilir |
| `CLIP 0.xx` | CLIP resim-resim kosinüsü ≥ 0.85 (`--clip`) — "benziyor", diğerlerinden zayıf |

### Dört aşama, sırayla

Görsel boru hattı katmanlı: her aşama yalnızca bir öncekinin geçirdiğine bakar.

| # | Aşama | Ne yapar | Eşleşme üretebilir mi? |
|---|---|---|---|
| 1 | hash | SHA-256, dHash, pHash, merkez kırpım | evet |
| 2 | InsightFace | ArcFace `buffalo_l` gömmeleri, kosinüs ≥ eşik | evet |
| 3 | DeepFace | Facenet512 + VGG-Face, 2. aşamanın eşleştirdiği çiftleri denetler | **hayır, yalnız onaylar ya da reddeder** |
| 4 | CLIP | ViT-B/32 anlamsal benzerlik, yüz aşamalarından bağımsız | evet, "benziyor" olarak |

3. aşama tasarım gereği doğrulayıcı. Yüz içermeyen görsellerde (logolar, harf avatarları) kendi başına
puanladığında DeepFace üç alakasız logoyu `verified` ilan etti, InsightFace ise doğru şekilde çekimser
kaldı; bu yüzden DeepFace'in eşleşme önermesine izin verilmiyor. Çift başına verdiği karar şunlardan biri:

| Karar | Anlamı | Sonuç |
|---|---|---|
| `confirmed` | her DeepFace modeli InsightFace ile hemfikir | yeşil etiket |
| `disputed` | en az bir model eşleşmeyi reddediyor | kırmızı etiket, fotoğrafa damga |
| `abstained` | DeepFace'in dedektörü karar verecek yüz bulamadı | nötr etiket |

Damga yalnızca DeepFace'in **hiçbir** çiftte doğrulayamadığı fotoğrafa basılır; senin referansınla
doğrulanmış bir fotoğraf, başka bir eşleştirmesi reddedilse bile temiz kalır. Damga küçük resmin
içine işlenir (kırmızı çerçeve artı `DEEPFACE NOT CONFIRMED` bandı), böylece rapora, JSON çıktısına ve
fotoğrafın kopyalandığı her yere taşınır.

### Yerel görüntü yığını (`--faces`, `--deepface`, `--clip`)

`dashboard/install-ml.sh`, `ml/.venv` oluşturur (`uv` ile Python 3.12, CPU torch, InsightFace `buffalo_l`,
OpenCLIP ViT-B/32) ve modelleri bir kez `ml/models/` altına indirir; sonrasında `HF_HUB_OFFLINE=1`
aşamanın dışarıya bağlanmasını engeller. Venv de modeller de depoya girmez. Her şey senin CPU'nda
çalışır; hiçbir resim makineden çıkmaz. 72 px küçük resimden nadiren kullanılabilir yüz gömmesi
çıktığı için tarayıcı yakaladığı her avatarın 320 px kopyasını `images/` altında tutar.

DeepFace isteğe bağlı ve ağır: venv'e TensorFlow (~2 GB) ekler ve ~757 MB ağırlığı proje klasörünün
**dışında**, `~/.deepface/weights` altında tutar; 8. bölümdeki kaldırma adımlarında bunu unutma.
Kurmadan geçmek için `KARGU_SKIP_DEEPFACE=1 dashboard/install-ml.sh`; `--faces` ve `--clip` etkilenmez.
TensorFlow ile torch, ONNX Runtime'ın yanında aynı süreçte yüklendiğinde süreci çökertiyor, bu yüzden
DeepFace açıkken tarayıcı CLIP'i ayrı bir alt süreçte çalıştırır.

`--faces` ile tarama, **aynı yüzü** gösteren hesapları da kümeler (yalnız farklı sitelerde); hesap
tablosunda `face #n`, raporun 2. bölümünde *Same face* satırları olarak görünür.
`--deepface` bu kümedeki bir bağlantıyı reddederse satır bunu söyler (`DeepFace refused N link(s)`). Panel bitmiş bir vakada
iki analizi yeniden çalıştırabilir (`Run face matching`); sonuç dışa aktarımın yanına
`<vaka>.vision.json` olarak kaydedilir ve sonraki açılışta gösterilir. CLIP **metin araması**
("uniform", "tattoo", "glasses") yakalanan resimleri tarife göre sıralar.

Yüz gömmeleri özel nitelikli biyometrik veridir (KVKK md. 6 / GDPR md. 9): aşama her yerde isteğe
bağlıdır (bayrak, sihirbaz sorusu, onay kutusu, panelde onay) ve kosinüs skoru bir benzerliktir, kimlik
değil. İki temiz portre arasındaki `face 0.96` güçlü kanıttır; 40 px avatar ile grup fotoğrafı
arasındaki `0.52` gözle bakılacak bir ipucudur.

## 18) Açık akışlar: GDELT, Telegram, Sentinel-2

| Akış | Gerekli | Ne verir |
|---|---|---|
| GDELT DOC 2.0 (`feeds/gdelt.py`) | hiçbir şey | son 7 günde sorguyu anan haberler; 5 saniyede bir sorgu limiti var, panel buna göre sıraya sokar |
| Telegram araması (`feeds/telegram_search.py`) | `config/.env` içinde `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, bir kez etkileşimli `--login` | `TELEGRAM_CHANNELS` içinde sorguyla eşleşen mesajlar; boşsa Telegram'ın genel araması |
| Telegram dinleyicisi (`feeds/telegram_listener.py <vaka-klasörü>`) | aynı anahtarlar + `TELEGRAM_CHANNELS` | her mesajı `telegram.jsonl`'a ekleyen, vaka tohumlarını ananları işaretleyen bir daemon; panel isabetleri gösterir |
| Sentinel-2 (`feeds/sentinel.py`) | `COPERNICUS_CLIENT_ID/SECRET` (ücretsiz hesap) | bir koordinatın çevresinde son < %40 bulutlu sahneler, 10 m çözünürlük — arazi ve binalar, asla insan |

Akış sorguları (GDELT, Telegram, Sentinel-2) panelin çalıştığı makinenin kendi bağlantısından canlı gider: taramanın
Tor/proxychains rotasını kullanmazlar; vaka sayfasındaki çıkış etiketi tarama anında ölçülen rotadır.
Telethon `ml/.venv` içinde çalışır; atılabilir bir Telegram hesabı kullan — otomatik istemciler yasaklanır
ve oturum dosyası (`config/telegram.session`, git-ignore'da, mod 600) hesaba tam erişim verir.
Anahtarı eksik bir akış sayfayı bozmak yerine "skipped" / "not configured" der.

