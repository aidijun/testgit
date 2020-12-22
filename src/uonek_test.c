#include <stdio.h>
#include "uonek_dlms.h"
#include "uonek_target_os.h"
#include "uonek_test.h"
#include "dlms_config.h"
#ifdef UONEK_FEATURE_SUPPORT_DTLS
#include "dtls_config.h"
#include "file_for_dlms.h"
#include "test_dtls_secrets.h"
#endif
#include "test_hls.h"
#include "test_hmac.h"
#include "test_hash.h"
#include "test_key_agree.h"
#include "test_fw_update.h"
#include "test_user_data.h"
#include "test_sec_log.h"
#include "test_unlock.h"
#include "test_ecdsa.h"
#include "test_random.h"
#include "test_gcm.h"
#include "test_version.h"
#include "test_empty.h"
#include "test_eek.h"
#include "test_kepco_certi.h"
#include "test_certi.h"
#include "test_dev_fw_upgrade.h"
#include "test_measure_performance.h"
#ifdef UONEK_DLMS_RUNTIME_TEST_PERSO
#include "test_private_key.h"
#include "test_public_key.h"
#include "test_system_title.h"
#include "test_personalize.h"
#endif // UONEK_DLMS_RUNTIME_TEST_PERSO


#if !MBED_TEST_MODE

#if 0
uonek_testing_option g_uonek_t_o;
void uonek_set_testing_option(uonek_testing_option t_o)
{
    g_uonek_t_o = t_o;
}
#endif

sint32 uonek_unit_test(uonek_testing_option opt)
{
    int ret = 0;

#ifdef UONEK_DLMS_RUNTIME_TEST_PERSO
    if (UONEK_SE_TESTING_OPTION(READ_PUBKEY)) {
        ret |= testing_get_pubkey();
    }
    if (UONEK_SE_TESTING_OPTION(READ_CERTIFICATE)) {
        ret |= testing_get_certificate();
    }

#ifdef UONEK_SUPPORT_CSR    
    if (UONEK_SE_TESTING_OPTION(GENERATE_CSR)) {
        ret |= testing_generate_csr();
    }
#endif //  UONEK_DLMS_SUPPORT_CSR
    
    if (UONEK_SE_TESTING_OPTION(READ_CERTI_FIELD)) {
        ret |= testing_get_certi_field();
    }
    if (UONEK_FILE_TESTING_OPTION(CHANGE_PRIV_KEY)) {
        ret |= testing_change_private_key();
    }
    if (UONEK_SE_TESTING_OPTION(READ_SYSTEMTITLE)) {
        ret |= testing_get_system_title();
    }
    if (UONEK_SE_TESTING_OPTION(ECDSA_SIGN_VERIFY)) {
        ret |= test_hls_sign_verify();
    }
    if (UONEK_SE_TESTING_OPTION(KA_2E)) {
       ret |= test_key_agreement_2e_test();
    }

#ifdef INTERNAL_TEST        
    if (UONEK_SE_TESTING_OPTION(FIRMWARE_UPDATE)) {
        ret |= test_se_firmware_update();
    }
    
    if (UONEK_SE_TESTING_OPTION(UNLOCK)) {
        ret |= test_lock_unlock();
    }
#endif    
#endif
    
    if (UONEK_SE_TESTING_OPTION(VERIFY_CERTI)) {
        ret |= testing_verify_certi();
    }
    
    if (UONEK_SE_TESTING_OPTION(VERSION)) {
        ret |= test_version();
    }
    
    if (UONEK_SE_TESTING_OPTION(HMAC_SHA256)) { 
        ret |= test_hmac();
    }

    if (UONEK_SE_TESTING_OPTION(HASH_SHA256)) {
        ret |= test_do_hash();
    }

    if (UONEK_SE_TESTING_OPTION(USER_DATA)) {
        ret |= test_set_get_data();
    }

    if (UONEK_SE_TESTING_OPTION(SEC_LOG)) {
        ret |= test_set_get_security_log();
    }

    if (UONEK_SE_TESTING_OPTION(ECDSA_P256_SHA256)) {
        ret |= test_ecdsa();
    }

    if (UONEK_SE_TESTING_OPTION(RANDOM)) {
        ret |= test_generate_random();
    }

    if (UONEK_SE_TESTING_OPTION(GCM)) {
        ret |= test_gcm();
    }

    if (UONEK_SE_TESTING_OPTION(EEK)) {
        ret |= test_eek();
    }        

    if (UONEK_SE_TESTING_OPTION(EMPTY)) {
        ret |= test_empty();
    }

    if (UONEK_SE_TESTING_OPTION(KEPCO_CERTI)) {
        ret |= testing_kepco_certificate();
    }

    if (UONEK_SE_TESTING_OPTION(DEV_FW_UPGRADE)) {
        ret |= test_dev_fw_upgrade();
    }
    
    if (UONEK_SE_TESTING_OPTION(MEASURE_PERFORMANCE)) {
        ret |= test_measure_prformance();
    }
#ifndef DTLS_UBIVELOX_USE_SE
#if 0
    if (UONEK_TESTING_OPTION(PSK_PRF_SHZ)) {
        ret |= test_dtls_put_secrets();
        ret |= test_dtls_read_secrets();
        ret |= test_dtls_clean_secrets();
    }
#endif
#endif
#if 0
    if (UONEK_TESTING_OPTION(KCMVP_SELF_TEST)) {
        ret |= testing_kcmvp_self_test() != 0;
    }
#endif

    return ret;
}

#ifdef UONEK_DLMS_RUNTIME_TEST_PERSO
sint32 personalize_uonek(uonek_testing_option opt)
{
#ifndef DLMS_UBIVELOX_USE_SE
    if (UONEK_FILE_TESTING_OPTION(FILESYSTEM)) {
        if (init_uonek_filesystem() != 0) {
            goto perso_error;
        }
    }
#endif //!DLMS_UBIVELOX_USE_SE
    if (UONEK_SE_TESTING_OPTION(PUT_CERTI)) {
        if (testing_put_certificate() != 0) {
            goto perso_error;
        }
    }
    if (UONEK_SE_TESTING_OPTION(PUT_OPP_CERTI)) {
        if (testing_put_opp_certificate() != 0) {
            goto perso_error;
        }
    }
    if (UONEK_SE_TESTING_OPTION(CERTI_SYSTEMTITLE)) {
        if (testing_put_system_title_from_certi() != 0) {
            goto perso_error;
        }
    }
    else if (UONEK_SE_TESTING_OPTION(PUT_SYSTEMTITLE)) {
        if (testing_put_system_title() != 0) {
            goto perso_error;
        }
    }
#ifndef DLMS_UBIVELOX_USE_SE
    if (UONEK_FILE_TESTING_OPTION(PUT_DEFAULT_PIN)) {
        if (testing_put_default_pin() != 0) {
            goto perso_error;
        }
    }
    if (UONEK_FILE_TESTING_OPTION(PUT_USER_INFO)) {
        if (testing_create_info_file() != 0) {
            goto perso_error;
        } 
    }
#endif //!DLMS_UBIVELOX_USE_SE
    return 0;

perso_error:
    uonek_printf("perso error occurred\n");
    return -1;
}
#endif

#endif// !MBED_TEST_MODE
