#pragma once
#include <iostream>
#include <windows.h>
#include <thread>
#include <vector>
#include <TlHelp32.h>
#include "../include/xorstr.hpp" // derleme zamanı XOR kütüphanesi entegrasyonu

#pragma comment(lib, "ntdll.lib")
#pragma warning(disable:4996)

/**
 * @namespace Shield
 * @brief yerel güvenlik mekanizmaları ve tersine mühendislik karşıtı araştırma modülleri.
 */
namespace Shield 
{
    // sistem seviyesinde yanıtlar için gerekli Native API tanımlamaları
    extern "C" {
        NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
        NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);
    }

    /**
     * @brief Yüksek riskli bir tehdit algılandığında sistemi kontrollü bir şekilde durdurur.
     * bu fonksiyon, bellek dökümü (dump) alınmasını engellemek için son çare olarak kullanılır.
     */
    static void KritikSistemYaniti() {
        BOOLEAN bEtkin;
        ULONG uYanit;
        
        // gerekli kapatma ayrıcalıklarını ayarla (Shutdown Privilege)
        RtlAdjustPrivilege(19, TRUE, FALSE, &bEtkin);
        
        // STATUS_ASSERTION_FAILURE sinyali ile sistemi güvenli modda durdur (BSoD simülasyonu)
        NtRaiseHardError(0xC0000420L, 0, 0, NULL, 6, &uYanit);
    }

    /**
     * @brief toolhelp32 kütüphanesini kullanarak çalışan bir sürecin ID'sini bulur.
     */
    static int SurecKimligiBul(const char* hedef_isim) {
        HANDLE hAnlikGoruntu = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hAnlikGoruntu == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        int bulunan_pid = 0;

        if (Process32First(hAnlikGoruntu, &pe32)) {
            do {
                if (strcmp(hedef_isim, pe32.szExeFile) == 0) {
                    bulunan_pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hAnlikGoruntu, &pe32));
        }
        CloseHandle(hAnlikGoruntu);
        return bulunan_pid;
    }

    /**
     * @brief Win32 API üzerinden basit hata ayıklayıcı (debugger) tespiti yapar.
     */
    void HataAyiklayiciKontrolEt() {
        if (IsDebuggerPresent()) {
            exit(0);
        }
    }

    /**
     * @brief bilinen analiz ve tersine mühendislik araçlarını tarar.
     * süreç isimleri statik analizden kaçınmak için XOR ile gizlenmiştir.
     */
    void OrtamTaramaGerceklestir() {
        const std::vector<std::string> kara_liste = {
            ProtectedStr("ollydbg.exe").get_raw(),
            ProtectedStr("x64dbg.exe").get_raw(),
            ProtectedStr("ida64.exe").get_raw(),
            ProtectedStr("ProcessHacker.exe").get_raw(),
            ProtectedStr("windbg.exe").get_raw()
        };

        for (const auto& surec : kara_liste) {
            if (SurecKimligiBul(surec.c_str()) != 0) {
                exit(0);
            }
        }
    }

    /**
     * @brief düşük seviyeli analiz araçlarına ait sürücülerin (driver) varlığını denetler.
     */
    void SurucuTabanliAnalizTespitEt() {
        const char* kernel_aygitlari[] = {
            ProtectedStr("\\\\.\\kdstinker").get_raw(),
            ProtectedStr("\\\\.\\KsDumper").get_raw()
        };

        for (const char* aygit : kernel_aygitlari) {
            HANDLE hDosya = CreateFileA(aygit, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDosya != INVALID_HANDLE_VALUE) {
                CloseHandle(hDosya);
                KritikSistemYaniti(); // tehdit algılandığında sistemi durdur
            }
        }
    }
}
