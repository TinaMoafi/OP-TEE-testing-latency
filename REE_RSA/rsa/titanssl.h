#ifndef TITANSSL_H
#define TITANSSL_H



typedef struct {
  unsigned long data_addr;
  unsigned long data_size;
  unsigned long data_nop;  // Number of Pages
  unsigned long page_size; 
  unsigned long page_fpo;
  unsigned long page_fps;
  unsigned long page_lps;
} titanssl_page_info_t;







typedef struct {
  unsigned int magic_number;  // 0xEC5FBEC5
  
  unsigned int input_dsz;   // Data Size
  unsigned int input_nop;   // Number of pages
  unsigned int input_fpo;   // First Page Offset
  unsigned int input_fps;   // First Page Size
  unsigned int input_lps;   // Last Page Size
  unsigned int input_map;   // Address to Master Page
  
  unsigned int output_dsz;  // Data Size
  unsigned int output_nop;  // Number of pages
  unsigned int output_fpo;  // First Page Offset
  unsigned int output_fps;  // First Page Size
  unsigned int output_lps;  // Last Page Size
  unsigned int output_map;  // Address to Master Page

  unsigned int meta_dsz;    // Data Size
  unsigned int meta_nop;    // Number of pages
  unsigned int meta_fpo;    // First Page Offset
  unsigned int meta_fps;    // First Page Size
  unsigned int meta_lps;    // Last Page Size
  unsigned int meta_map;    // Address to Master Page
} __attribute__((__packed__)) titanssl_mbox_header_t;

#endif  // TITANSSL_H
