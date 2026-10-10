; Good Bear NSIS branding definitions for the offline Windows installer.
; The stub installer is not a release channel; its fallback URLs describe the
; public Good Bear project without using Mozilla download infrastructure.
!define BrandFullNameInternal "Good Bear"
!define BrandFullName         "Good Bear"
!define CompanyName           "Good Bear"
!define URLInfoAbout          "https://github.com/Goudron/good-bear"
!define URLUpdateInfo         "https://github.com/Goudron/good-bear/releases"
!define HelpLink              "https://github.com/Goudron/good-bear/issues"

!define URLStubDownloadX86 "https://github.com/Goudron/good-bear/releases"
!define URLStubDownloadAMD64 "https://github.com/Goudron/good-bear/releases"
!define URLStubDownloadAArch64 "https://github.com/Goudron/good-bear/releases"
!define URLManualDownload "https://github.com/Goudron/good-bear/releases"
!define URLSystemRequirements "https://github.com/Goudron/good-bear#readme"
!define Channel "unofficial"

; Full offline installers are the Good Bear release artifact. These values make
; an accidental stub download fail closed instead of accepting an upstream file.
!define CertNameDownload   "Good Bear"
!define CertIssuerDownload "Good Bear"

!define PROFILE_CLEANUP_LABEL_TOP "35u"
!define PROFILE_CLEANUP_LABEL_LEFT "0"
!define PROFILE_CLEANUP_LABEL_WIDTH "100%"
!define PROFILE_CLEANUP_LABEL_HEIGHT "80u"
!define PROFILE_CLEANUP_LABEL_ALIGN "center"
!define PROFILE_CLEANUP_CHECKBOX_LEFT "center"
!define PROFILE_CLEANUP_CHECKBOX_WIDTH "100%"
!define PROFILE_CLEANUP_BUTTON_LEFT "center"
!define INSTALL_BLURB_TOP "137u"
!define INSTALL_BLURB_WIDTH "60u"
!define INSTALL_FOOTER_TOP "-48u"
!define INSTALL_FOOTER_WIDTH "250u"
!define INSTALL_INSTALLING_TOP "70u"
!define INSTALL_INSTALLING_LEFT "0"
!define INSTALL_INSTALLING_WIDTH "100%"
!define INSTALL_PROGRESS_BAR_TOP "112u"
!define INSTALL_PROGRESS_BAR_LEFT "20%"
!define INSTALL_PROGRESS_BAR_WIDTH "60%"
!define INSTALL_PROGRESS_BAR_HEIGHT "12u"

!define PROFILE_CLEANUP_CHECKBOX_TOP_MARGIN "20u"
!define PROFILE_CLEANUP_BUTTON_TOP_MARGIN "20u"
!define PROFILE_CLEANUP_BUTTON_X_PADDING "40u"
!define PROFILE_CLEANUP_BUTTON_Y_PADDING "4u"

!define INSTALL_HEADER_FONT_SIZE 28
!define INSTALL_HEADER_FONT_WEIGHT 400
!define INSTALL_INSTALLING_FONT_SIZE 28
!define INSTALL_INSTALLING_FONT_WEIGHT 400

!define COMMON_TEXT_COLOR 0xFFFFFF
!define COMMON_BACKGROUND_COLOR 0x1F310B
!define INSTALL_INSTALLING_TEXT_COLOR 0xFFFFFF
!define PROGRESS_BAR_BACKGROUND_COLOR 0x4AB5E6
