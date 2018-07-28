/* ***************************************************************************
 Name: Max N. Philip
 Student Number: 836472
 Login ID: mphilip1

 Program written by Max Philip for Assignment 2 of Computer Systems (COMP20023)
 Semester 1, 2018.

 C program that reads in a CSV file of paths to TLS certificate files and the
 URL from which the certificate belongs. The program then steps through each
 line of the CSV file, loads the specified certificate and validates it, also
 checking the following  URL. For every line, the program writes to another
 CSV file, keeping the same input columns and adding a "valid" column with the
 value 1 if the certificate is valid and 0 if it is invalid.

 The code provided in the Assignment git repository was used as a basis for
 this program, primarily for initially reading the certificates and extracting
 certificate extensions.
 Repo URL: https://gitlab.eng.unimelb.edu.au/COMP30023/Assignment2.git

**************************************************************************** */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ************************************************************************* */

// field values
#define COMMON_NAME_EQ  "CN="
#define BASIC_CON_F     "CA:FALSE"
#define KEY_USAGE       "TLS Web Server Authentication"

#define BYTE_BITS       8
#define MIN_RSA_LEN     2048
#define BUF_SIZE        256
#define LARG_BUF        1024

// characters
#define NULL_BYTE       '\0'
#define COMMA           ","
#define F_SLASH         "/"
#define FULL_STOP       "."
#define COMMA_SPACE     ", "
#define STRP_NEWLINE    "\r\n"
#define WILD            "*"

// numbers
#define DNS_OFFSET      4
#define CA_OFFSET       3
#define SPACE_OFFSET    1

/* ************************************************************************* */

/* FUNCTION PROTOTYPES */
const char * get_extension(X509_EXTENSION *ex);
int check_key_usage(X509_EXTENSION *ex_key);
int check_alt_name(X509_EXTENSION *ex, char *out_url);
int check_basic_constraints(X509_EXTENSION *ex);
int domain_validation(char *url, char *common_name);
void string_slice(char *my_str, char *buf, int start, int end);
const char * get_domain(X509 cert);
char * shift_string_left(char *my_str);
int check_date(X509 cert);
int get_rsa_bits(X509 cert);
int pass_all_checks(int date, int rsa_bits, int domain, int basic_con,
                                            int alt_name, int key_usage);

/* ************************************************************************* */

/* FUNCTION DEFINITIONS */

int main(int argc, char **argv)
{

    /* Initialise openSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Read in the CSV from command line input */
    FILE *file = fopen(argv[1], "r");

    char *line;
    char *cert_path, *url;
    char buffer[LARG_BUF];

    /* Initialise the output CSV file */
    FILE *output_file;
    output_file = fopen("output.csv", "w+");

    if (!file)
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    /* Read the CSV file line by line */
    while ((line = fgets(buffer, sizeof(buffer), file)) != NULL)
    {
        cert_path = strtok(line, COMMA);
        url = strtok(NULL, COMMA);

        /* Strip trailing newline at the end of the URL */
        url[strcspn(url, STRP_NEWLINE)] = 0;

        char out_url[BUF_SIZE], out_path[BUF_SIZE];
        strcpy(out_url, url);
        strcpy(out_path, cert_path);

        BIO *certificate_bio = NULL;
        X509 *cert = NULL;

        /* Create BIO object to read certificate */
        certificate_bio = BIO_new(BIO_s_file());

        /* Read certificate into BIO */
        if (!(BIO_read_filename(certificate_bio, cert_path)))
        {
            fprintf(stderr, "Error in reading cert BIO filename");
            exit(EXIT_FAILURE);
        }
        if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
        {
            fprintf(stderr, "Error in loading certificate");
            exit(EXIT_FAILURE);
        }

        /* Begin validation checks */

        /* Validates the Not Before and Not After dates */
        int date = check_date(*cert);

        /* RSA bits */
        int rsa_bits = get_rsa_bits(*cert);

        /* Validates whether the domain name is in the Common name*/
        char common_name[BUF_SIZE];
        strcpy(common_name, get_domain(*cert));
        int valid_domain = domain_validation(url, common_name);

        /* Validate whether the URL is present in the certificate's alternate
           names */
        X509_EXTENSION *ex_alt = X509_get_ext(cert,
                        X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
        int alt_name_valid = check_alt_name(ex_alt, out_url);

        /* Validate the certificate's BasicConstraints (CA:FALSE)*/
        X509_EXTENSION *ex_basic_con = X509_get_ext(cert,
                        X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
        int valid_basic_con = check_basic_constraints(ex_basic_con);

        /* Checks if "TLS Web Server Authentication" is in the certificate's
           Enhanced Key Usage */
        X509_EXTENSION *ex_key = X509_get_ext(cert,
                            X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
        int valid_key_usage = check_key_usage(ex_key);

        /* Using all the previous validations, check whether the certificate
           passes the required tests */
        int passed_all = pass_all_checks(date, rsa_bits, valid_domain,
                            valid_basic_con, alt_name_valid, valid_key_usage);

        /* Write the two input values, and whether the certificate is valid,
        to the output CSV file */
        fprintf(output_file, "%s,%s,%d\n", out_path, out_url, passed_all);

        X509_free(cert);
        BIO_free_all(certificate_bio);
    }
    fclose(output_file);
    exit(0);
}


/* Helper function that gets the X509 extension. Returns the extension as a
   string */
const char * get_extension(X509_EXTENSION *ex)
{
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[LARG_BUF];
    OBJ_obj2txt(buff, LARG_BUF, obj, 0);

    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    if (strlen(buff) > 0)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(bio, ex, 0, 0))
        {
            fprintf(stderr, "Error in reading extensions");
        }
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bptr);

        //bptr->data is not NULL terminated - add null character
        buf = (char *)malloc((bptr->length + 1) * sizeof(char));
        memcpy(buf, bptr->data, bptr->length);
        buf[bptr->length] = NULL_BYTE;

    }
    return buf;
}


/* Validate whether the Enhanced Key Usage contains the "TLS Web Server
   Authentication" string. */
int check_key_usage(X509_EXTENSION *ex_key)
{
    char key_usages[BUF_SIZE], *usage, key_nospace[BUF_SIZE], temp[BUF_SIZE];

    strcpy(key_usages, get_extension(ex_key));
    usage = strtok(key_usages, COMMA);

    /* If the correct key usage is the only one existing in the certificate,
       then immediately validate */
    if (strcmp(usage, KEY_USAGE) == 0)
    {
        return 1;
    }

    /* Tokenize the rest of the string if there are more */
    while(usage != NULL)
    {
        usage = strtok(NULL, ",");
        if (usage)
        {
            strcpy(temp, usage);
            string_slice(temp, key_nospace, SPACE_OFFSET, strlen(temp));

            /* Return 1 if any of the following usages are correct */
            if (strcmp(key_nospace, KEY_USAGE) == 0)
            {
                return 1;
            }
        }
    }
    return 0;
}


/* Check if the input URL matches any certificate Subject Alternative Name
   (SAN) extensions, including wildcards */
int check_alt_name(X509_EXTENSION *ex, char *out_url)
{
    char alt_names[BUF_SIZE], alt_names_strip[BUF_SIZE], test_name[BUF_SIZE];
    char *name, name_strip[BUF_SIZE], *strp_alts[BUF_SIZE];
    int i=0;

    if (get_extension(ex)){

        /* Strip the "DNS:" prefix from the first SAN, if it exists */
        strcpy(alt_names, get_extension(ex));
        string_slice(alt_names, alt_names_strip, DNS_OFFSET, strlen(alt_names));

        /* Tokenize the string containing all the alternate names by ",". Then
           store each stripped name in an array */
        name = strtok(alt_names_strip, COMMA);
        strp_alts[i] = name;

        while(name != NULL)
        {
            name = strtok(NULL, COMMA_SPACE);
            if (name){

                /* Strip the "DNS:" prefix from each SAN */
                strcpy(test_name, name);
                string_slice(test_name, name_strip, DNS_OFFSET, strlen(name));
                i++;
                strp_alts[i] = strdup(name_strip);
            }
        }

        /* Validate each SAN, and return 1 if any of the names are valid */
        for (int j=0; j <= i; j++){
            if (domain_validation(out_url, strp_alts[j])){
                return 1;
            }
        }
    }
    return 0;
}


/* Validates whether BasicConstraints include the "CA:FALSE" string */
int check_basic_constraints(X509_EXTENSION *ex)
{
    char basic_constraints[BUF_SIZE];
    strcpy(basic_constraints, get_extension(ex));
    if (strcmp(basic_constraints, BASIC_CON_F) == 0)
    {
        return 1;
    }
    return 0;
}


/* Validates the domain name based on the certificate's common names only.
   SAN checking is done elsewhere. Returns 1 if the certificate is valid */
int domain_validation(char *url, char *common_name)
{
    /* Immediately validate if the common name and domain name are the same */
    if (strcmp(url, common_name) == 0)
    {
        return 1;
    }

    char t_url[BUF_SIZE], t_com_name[BUF_SIZE];
    char *dom2_in, *dom3_in;
    char * dom1_out, *dom2_out, *dom3_out;

    strcpy(t_url, url);
    strcpy(t_com_name, common_name);

    /* Tokenize the input URL, and common name being checked, by "." char. */
    strtok(t_url, FULL_STOP);
    dom2_in = strtok(NULL, FULL_STOP);
    dom3_in = strtok(NULL, FULL_STOP);

    dom1_out = strtok(t_com_name, FULL_STOP);
    dom2_out = strtok(NULL, FULL_STOP);
    dom3_out = strtok(NULL, FULL_STOP);

    /* Check if the common name in the certificate is a wildcard */
    if (strcmp(dom1_out, WILD) == 0)
    {
        if (strcmp(dom2_in, dom2_out) == 0 && strcmp(dom3_in, dom3_out) == 0)
        {
            return 1;
        }
    }
    return 0;
}


/* Get the common names from the certificate, stripping the "CA=" prefix */
const char * get_domain(X509 cert)
{
    char cn[100], *token, *domain;
    char eq[8];

    /* Tokenize the common name by "/", separating each of the common names */
    strcpy(cn, (&cert)->name);
    token = strtok(cn, F_SLASH);
    while(token != NULL)
    {
        /* Strip the "CA=" from each string */
        string_slice(token, eq, 0, CA_OFFSET);
        if (strcmp(eq, COMMON_NAME_EQ) == 0)
        {
            domain = malloc(LARG_BUF);
            string_slice(token, domain, CA_OFFSET, strlen(token));
            break;
        }
        token = strtok(NULL, F_SLASH);
    }
    return domain;
}


/* Helper function that slices an input string from a start and end position,
   assigning the new string to another input string */
void string_slice(char *my_str, char *new_str, int start, int end)
{
    int i=0, j=0;
    for (i = start; i < end; i++)
    {
        new_str[j] = my_str[i];
        j++;
    }
    new_str[j] = NULL_BYTE;
}


/* Check whether the key length for RSA is at least 2048 bits. */
int get_rsa_bits(X509 cert)
{
    EVP_PKEY *pub_key = X509_get_pubkey(&cert);
    RSA *rsa_key = EVP_PKEY_get1_RSA(pub_key);
    int k_len = RSA_size(rsa_key);
    RSA_free(rsa_key);

    /* Return 1 if the key length is long enough */
    if (k_len*BYTE_BITS >= MIN_RSA_LEN)
    {
        return 1;
    }
    return 0;
}


/* Check whether the Not Before (Issue) and Not After (Expiration) dates are
   valid. Return 1 if both are valid, otherwise return 0. */
   int check_date(X509 cert)
   {
       const ASN1_TIME *issue_date = X509_get_notBefore(&cert);
       const ASN1_TIME *exp_date = X509_get_notAfter(&cert);
       int days, secs;
       int is_valid = 1;

       /* If the Not After date is after the current date, then invalid.
          If the Not Before date is before the current date, then invalid. */
       if (!ASN1_TIME_diff(&days, &secs, NULL, exp_date))
       {
           is_valid = 0;
       }
       if (days < 0 || secs < 0)
       {
           is_valid = 0;
       }
       if (!ASN1_TIME_diff(&days, &secs, NULL, issue_date))
       {
           is_valid = 0;
       }
       if (days > 0 || secs > 0)
       {
           is_valid = 0;
       }
       return is_valid;
   }


/* Checks that the certificate is valid with all the tested criteria */
int pass_all_checks(int date, int rsa_bits, int domain, int basic_con,
                                            int alt_name, int key_usage)
{
    /* All checks must be true, except for domain, which only needs either the
       domain or SAN to be valid*/
    if (date && rsa_bits && (domain || alt_name) && basic_con && key_usage)
    {
        return 1;
    } else {
        return 0;
    }
}
