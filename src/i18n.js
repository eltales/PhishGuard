"use strict";

globalThis.PGI18n = (() => {
  const messages = {
    optionsTitle: ["PhishGuard — Settings", "PhishGuard — Ustawienia"],
    optionsSubtitle: ["Phishing protection settings", "Konfiguracja ochrony przed phishingiem"],
    language: ["Language", "Język"],
    companyEmailTitle: ["Company email address", "Firmowy adres e-mail"],
    companyEmail: ["Your company email address", "Twój firmowy adres e-mail"],
    companyEmailHint: ["The domain is detected automatically and added to your company domains.", "Domena zostanie automatycznie wykryta i dodana do listy firmowych domen."],
    companyDomainsTitle: ["Company domains", "Firmowe domeny"],
    companyDomains: ["Company domains (one per line)", "Domeny firmowe (jedna na linię)"],
    companyDomainsHint: ["PhishGuard checks sender and link domains for similarities to these domains.", "PhishGuard sprawdza podobieństwo domen nadawców i linków do tych domen."],
    adminTitle: ["Administrator / IT security", "Administrator / IT Security"],
    adminEmail: ["Administrator email address", "Adres e-mail administratora"],
    adminEmailHint: ["PhishGuard fills in this address when you prepare a report.", "PhishGuard wpisze ten adres podczas przygotowywania zgłoszenia."],
    trustedDomainsTitle: ["Trusted domains", "Zaufane domeny"],
    trustedDomains: ["Trusted domains (one per line)", "Zaufane domeny (jedna na linię)"],
    trustedDomainsHint: ["Trust lowers the score for messages without lookalike domains or dangerous attachments.", "Zaufanie obniża wynik wiadomości bez domen podszywających się pod firmę lub niebezpiecznych załączników."],
    blockedDomain: ["The domain {0} resembles a company domain or uses mixed-script lookalikes. It cannot be added to trusted domains.", "Domena {0} przypomina domenę firmową lub używa znaków podobnych z różnych alfabetów. Nie można jej dodać do zaufanych."],
    trustRestricted: ["This message cannot be marked safe.", "Tej wiadomości nie można oznaczyć jako bezpiecznej."],
    markSafeFailed: ["Could not mark this message safe.", "Nie udało się oznaczyć wiadomości jako bezpiecznej."],
    linkSettings: ["Link warnings", "Ostrzeżenia przy linkach"],
    warnTagged: ["Warn before opening any link in a flagged message", "Ostrzegaj przy każdym linku w wiadomości oznaczonej jako podejrzana"],
    warnSuspicious: ["Warn before opening suspicious links in any message", "Ostrzegaj przy podejrzanych linkach w każdej wiadomości"],
    reportSettings: ["Reporting to the administrator", "Zgłaszanie do administratora"],
    reportButtonSetting: ["Enable the report button in the main Thunderbird toolbar and message warnings", "Włącz przycisk zgłaszania na głównym pasku Thunderbirda i w ostrzeżeniach nad wiadomością"],
    reportButtonHint: ["Analysis and warnings continue if you hide the button.", "Analiza i ostrzeżenia działają także po ukryciu przycisku."],
    save: ["Save settings", "Zapisz ustawienia"],
    saved: ["✓ Settings saved.", "✓ Ustawienia zostały zapisane."],
    detectedDomain: ["✓ Company domain detected: {0}", "✓ Wykryta domena firmowa: {0}"],
    invalidCompanyEmail: ["Enter a valid company email address.", "Wpisz poprawny firmowy adres e-mail."],
    invalidAdminEmail: ["Enter a valid administrator email address.", "Wpisz poprawny adres e-mail administratora."],
    detailsTitle: ["PhishGuard — Analysis details", "PhishGuard — Szczegóły analizy"],
    noAnalysis: ["No analysis available for this message.", "Brak analizy dla tej wiadomości."],
    noSignals: ["This message shows no signs of phishing.", "Ta wiadomość nie wykazuje sygnałów phishingu."],
    notConfigured: ["PhishGuard is not configured.", "PhishGuard nie jest skonfigurowany."],
    configure: ["Open settings to add your company email address.", "Otwórz ustawienia, aby dodać firmowy adres e-mail."],
    openOptions: ["Open settings", "Otwórz ustawienia"],
    risk: ["Risk level", "Poziom ryzyka"],
    score: ["Score", "Wynik"],
    reasons: ["Reasons for flagging", "Powody oznaczenia"],
    links: ["Suspicious links", "Podejrzane linki"],
    attachments: ["Suspicious attachments", "Podejrzane załączniki"],
    report: ["Report to administrator", "Zgłoś do administratora"],
    toolbar: ["Report phishing", "Zgłoś phishing"],
    preparing: ["Preparing…", "Przygotowywanie…"],
    prepared: ["✓ Report prepared", "✓ Raport przygotowany"],
    reportFailed: ["Could not prepare the report.", "Nie udało się przygotować raportu."],
    error: ["Error", "Błąd"],
    details: ["Details", "Szczegóły"],
    markSafe: ["Mark as safe locally", "Oznacz jako bezpieczne lokalnie"],
    close: ["Close", "Zamknij"],
    low: ["Low", "Niskie"],
    medium: ["Medium", "Średnie"],
    high: ["High", "Wysokie"],
    critical: ["Critical", "Krytyczne"],
    warning_medium: ["PhishGuard: Use caution with this message", "PhishGuard: Ta wiadomość wymaga ostrożności"],
    warning_high: ["PhishGuard: High phishing risk", "PhishGuard: Wysokie ryzyko phishingu"],
    warning_critical: ["PhishGuard: Critical phishing risk", "PhishGuard: Krytyczne ryzyko phishingu"],
    advice_medium: ["Check the sender and link destinations before clicking.", "Sprawdź nadawcę i adresy docelowe linków przed kliknięciem."],
    advice_high: ["Check the sender before opening any links or attachments.", "Sprawdź nadawcę przed otwarciem linków lub załączników."],
    advice_critical: ["PhishGuard detected several strong phishing signals. Consider reporting this message to your administrator.", "PhishGuard wykrył silne sygnały phishingu. Rozważ zgłoszenie wiadomości administratorowi."],
    senderDomainHint: ["Sender domain: {0}", "Domena nadawcy: {0}"],
    linkDomainHint: ["Domain: {0}", "Domena: {0}"],
    none: ["(none)", "(brak)"],
    linkText: ["Visible text", "Widoczny tekst"],
    destination: ["Destination URL", "Adres docelowy"],
    reason: ["Reason", "Powód"],
    linkWarning: ["PhishGuard: Potentially unsafe link", "PhishGuard: Potencjalnie niebezpieczny link"],
    linkWarningBody: ["PhishGuard flagged this message or link as potentially unsafe.", "PhishGuard oznaczył tę wiadomość lub link jako potencjalnie niebezpieczne."],
    openLinkQuestion: ["Do you want to open this link?", "Czy chcesz otworzyć ten link?"],
    cancel: ["Cancel", "Anuluj"],
    openLink: ["Open link", "Otwórz link"],
    tagged_email: ["Link in a flagged message", "Link w oznaczonej wiadomości"],
    reportTitle: ["PhishGuard for Thunderbird — Suspicious message report", "PhishGuard for Thunderbird — Raport podejrzanej wiadomości"],
    reportDate: ["Report date", "Data zgłoszenia"],
    originalSender: ["Original sender", "Oryginalny nadawca"],
    subject: ["Subject", "Temat"],
    messageDate: ["Message date", "Data wiadomości"],
    reportFooter: ["Report generated by PhishGuard for Thunderbird.", "Zgłoszenie wygenerowane przez PhishGuard for Thunderbird."],
    unknown: ["unknown", "nieznany"],
    noSubject: ["(no subject)", "(brak tematu)"],
    missingAdmin: ["Add an administrator email address in PhishGuard settings.", "Dodaj adres e-mail administratora w ustawieniach PhishGuard."],
    readHeadersFailed: ["Could not read the message headers.", "Nie można pobrać nagłówków wiadomości."],
    attachFailed: ["Could not attach the original message.", "Nie można dołączyć oryginalnej wiadomości."],
    originalFilename: ["original-message.eml", "oryginalna-wiadomosc.eml"],
    sender_lookalike_domain: ["Sender domain resembles a company domain", "Domena nadawcy jest bardzo podobna do domeny firmowej"],
    link_domain_lookalike: ["Link domain resembles a company domain", "Domena linku jest bardzo podobna do domeny firmowej"],
    link_text_href_mismatch: ["Visible link text differs from the destination", "Tekst linku nie zgadza się z adresem docelowym"],
    reply_to_mismatch: ["Reply-To differs from From", "Reply-To różni się od From"],
    reply_to_public_domain: ["Reply-To uses a public email provider", "Reply-To prowadzi do publicznej skrzynki pocztowej"],
    link_ip_address: ["Link uses an IP address", "Link prowadzi do adresu IP zamiast domeny"],
    link_shortener: ["Link uses a URL shortener", "Link używa serwisu skracającego URL"],
    link_punycode: ["Link domain uses Punycode (IDN)", "Link zawiera kodowanie punycode/IDN"],
    suspicious_attachment: ["Suspicious attachment", "Podejrzany załącznik"],
    urgency_subject: ["Subject uses urgent language", "Temat zawiera wyrazy presji czasowej"],
    urgency_body: ["Message uses urgent language", "Treść zawiera wyrazy presji czasowej"],
    many_links: ["Message contains many links", "Wiadomość zawiera dużo linków"],
    punycode_domain: ["Sender domain uses Punycode", "Domena nadawcy używa kodowania punycode"],
    trusted_domain: ["Domain is on the trusted list", "Domena na liście zaufanych"],
    known_sender: ["Known sender", "Znany nadawca"],
    homoglyph_exact_match: ["Domain contains lookalike characters", "Znaki wizualnie podobne w domenie"],
    homoglyph_sld_match: ["Domain name contains lookalike characters", "Znaki wizualnie podobne w nazwie domeny"],
    mixed_script_homoglyphs: ["Message mixes lookalike letters from different scripts within a word", "Wiadomość miesza podobne wizualnie litery z różnych alfabetów w jednym słowie"],
    levenshtein_distance_1: ["Domain differs by one character", "Domena różni się jednym znakiem"],
    levenshtein_distance_2: ["Domain differs by two characters", "Domena różni się dwoma znakami"],
    levenshtein_sld_distance_1: ["Domain name differs by one character", "Nazwa domeny różni się jednym znakiem"],
    transposition_detected: ["Domain contains transposed characters", "Przestawione znaki w domenie"],
    brand_substring_abuse: ["Domain contains the company name", "Domena zawiera nazwę firmy jako fragment"],
    tld_swap: ["Domain uses a different top-level domain", "Domena używa innej końcówki"],
    auth_dmarc_fail: ["DMARC check failed", "Wiadomość nie przeszła weryfikacji DMARC"],
    auth_spf_fail: ["SPF check failed", "Wiadomość nie przeszła weryfikacji SPF"],
    auth_dkim_fail: ["DKIM check failed", "Wiadomość nie przeszła weryfikacji DKIM"],
    display_name_spoofs_company: ["Sender name impersonates the company", "Nazwa nadawcy podszywa się pod firmę"],
    display_name_domain_mismatch: ["Sender name suggests a different domain", "Nazwa nadawcy sugeruje inną domenę"],
    display_name_is_email: ["Sender name impersonates a different email address", "Nazwa nadawcy udaje inny adres e-mail"],
    double_extension: ["Attachment has a double extension (e.g. .pdf.exe)", "Załącznik z podwójnym rozszerzeniem (np. .pdf.exe)"],
    mime_extension_mismatch: ["Attachment type differs from its extension", "Typ pliku nie zgadza się z rozszerzeniem załącznika"],
    plik_wykonywalny: ["High-risk executable file", "Plik wykonywalny — wysokie ryzyko"],
    dokument_z_makrami: ["Office document with macros", "Dokument Office z makrami"],
    archiwum: ["Archive may contain other files", "Archiwum może zawierać ukryte pliki"],
    podejrzane_rozszerzenie: ["Suspicious file extension", "Podejrzane rozszerzenie pliku"],
    url_userinfo: ["Link contains @ before the destination domain", "Link zawiera znak @ przed domeną docelową"],
    url_many_subdomains: ["Link has many subdomains or a long hostname", "Link ma dużo subdomen lub długą nazwę hosta"],
    url_abused_tld: ["Link uses a frequently abused top-level domain", "Link używa często nadużywanej końcówki domeny"],
    credential_request: ["Message requests login or payment information", "Wiadomość prosi o dane logowania lub płatności"],
    image_only_body: ["Message is mostly an image", "Treść wiadomości to głównie obraz"],
    language_mismatch: ["Writing system differs from the sender domain's usual language", "Alfabet treści nie pasuje do domeny nadawcy"],
  };

  function normalize(language) {
    return language === "pl" ? "pl" : "en";
  }

  function forLanguage(language) {
    const index = normalize(language) === "pl" ? 1 : 0;
    return (key, ...values) => {
      const labels = Object.hasOwn(messages, key) ? messages[key] : null;
      return (labels?.[index] ?? String(key)).replace(/\{(\d+)\}/g, (_, i) => values[i] ?? "");
    };
  }

  function localizeDocument(doc, language) {
    const t = forLanguage(language);
    doc.documentElement.lang = normalize(language);
    for (const element of doc.querySelectorAll("[data-i18n]")) {
      element.textContent = t(element.dataset.i18n);
    }
  }

  return { normalize, forLanguage, localizeDocument };
})();

// Thunderbird clones the completion value of each registered script.
void 0;
