import sys
import csv
import json

# Check if user gave us a file
if len(sys.argv) != 2:
    print("Usage: python3 detector_full_candidate_name.py input_file.csv")
    sys.exit(1)

input_filename = sys.argv[1]
output_filename = "redacted_output_candidate_full_name.csv"

# I'll check each type of PII one by one
def count_digits_in_string(text):
    # Count how many digits are in a string
    count = 0
    text = str(text)
    for character in text:
        if character >= '0' and character <= '9':
            count = count + 1
    return count

def extract_digits_only(text):
    # Get only the digit characters
    result = ""
    text = str(text)
    for character in text:
        if character >= '0' and character <= '9':
            result = result + character
    return result

def check_if_phone(text, field_name):
    # Phone numbers have exactly 10 digits
    digit_count = count_digits_in_string(text)
    if digit_count == 10:
        # Also check if the field name suggests it's a phone
        field_lower = field_name.lower()
        if "phone" in field_lower:
            return True
        if "contact" in field_lower:
            return True  
        if "mobile" in field_lower:
            return True
        # If it's exactly 10 digits and nothing else, probably phone
        digits_only = extract_digits_only(text)
        if len(str(text).strip()) == 10 and digits_only == str(text).strip():
            return True
    return False

def check_if_aadhaar(text):
    # Aadhaar has exactly 12 digits
    digit_count = count_digits_in_string(text)
    if digit_count == 12:
        return True
    return False

def check_if_passport(text, field_name):
    # Passport has letters and numbers
    text = str(text).strip()
    if len(text) < 6 or len(text) > 9:
        return False
        
    has_letter = False
    has_digit = False
    
    for char in text:
        if char >= 'A' and char <= 'Z':
            has_letter = True
        if char >= 'a' and char <= 'z':
            has_letter = True
        if char >= '0' and char <= '9':
            has_digit = True
    
    # Check if field name is passport
    if "passport" in field_name.lower():
        if has_letter and has_digit:
            return True
    
    return False

def check_if_upi(text):
    # UPI has @ but no dots after @
    text = str(text)
    if "@" not in text:
        return False
    
    # Split by @
    parts = []
    current_part = ""
    for char in text:
        if char == "@":
            parts.append(current_part)
            current_part = ""
        else:
            current_part = current_part + char
    parts.append(current_part)
    
    if len(parts) != 2:
        return False
    
    # Check if second part (domain) has dots
    domain_part = parts[1]
    if "." in domain_part:
        return False
        
    return True

def check_if_email(text):
    # Email has @ and dots after @
    text = str(text)
    if "@" not in text:
        return False
    
    # Split by @
    parts = []
    current_part = ""
    for char in text:
        if char == "@":
            parts.append(current_part)
            current_part = ""
        else:
            current_part = current_part + char
    parts.append(current_part)
    
    if len(parts) != 2:
        return False
    
    # Check if second part has dots
    domain_part = parts[1]
    if "." in domain_part:
        return True
        
    return False

def check_if_full_name(text):
    # Name has multiple words
    text = str(text).strip()
    words = []
    current_word = ""
    
    for char in text:
        if char == " ":
            if current_word != "":
                words.append(current_word)
                current_word = ""
        else:
            current_word = current_word + char
    
    if current_word != "":
        words.append(current_word)
    
    if len(words) >= 2:
        return True
    return False

def mask_phone_number(phone_text):
    # Keep first 2 and last 2 digits
    digits = extract_digits_only(phone_text)
    if len(digits) == 10:
        masked = digits[0] + digits[1] + "XXXXXX" + digits[8] + digits[9]
        return masked
    else:
        return "HIDDEN_PHONE"

def mask_aadhaar_number(aadhaar_text):
    # Show only last 4 digits
    digits = extract_digits_only(aadhaar_text)
    if len(digits) == 12:
        masked = "XXXX XXXX " + digits[8] + digits[9] + digits[10] + digits[11]
        return masked
    else:
        return "HIDDEN_AADHAAR"

def mask_passport_number(passport_text):
    # Keep first character
    text = str(passport_text).strip()
    if len(text) > 0:
        masked = text[0] + "XXXXXXX"
        return masked
    else:
        return "HIDDEN_PASSPORT"

def mask_upi_id(upi_text):
    # Keep first 2 chars before @
    text = str(upi_text)
    
    # Find @ position
    at_position = -1
    for i in range(len(text)):
        if text[i] == "@":
            at_position = i
            break
    
    if at_position > 0:
        before_at = text[:at_position]
        after_at = text[at_position:]
        
        if len(before_at) >= 2:
            masked_before = before_at[0] + before_at[1] + "XXX"
        else:
            masked_before = "XXX"
        
        return masked_before + after_at
    else:
        return "HIDDEN_UPI"

def mask_email_address(email_text):
    # Keep first 2 chars before @
    text = str(email_text)
    
    # Find @ position
    at_position = -1
    for i in range(len(text)):
        if text[i] == "@":
            at_position = i
            break
    
    if at_position > 0:
        before_at = text[:at_position]
        after_at = text[at_position:]
        
        if len(before_at) >= 2:
            masked_before = before_at[0] + before_at[1] + "XXX"
        else:
            masked_before = "XXX"
        
        return masked_before + after_at
    else:
        return "HIDDEN_EMAIL"

def mask_name(name_text):
    # Keep first letter of each word
    text = str(name_text).strip()
    words = []
    current_word = ""
    
    for char in text:
        if char == " ":
            if current_word != "":
                words.append(current_word)
                current_word = ""
        else:
            current_word = current_word + char
    
    if current_word != "":
        words.append(current_word)
    
    masked_words = []
    for word in words:
        if len(word) >= 1:
            masked_word = word[0]
            for i in range(1, len(word)):
                masked_word = masked_word + "X"
            masked_words.append(masked_word)
        else:
            masked_words.append(word)
    
    result = ""
    for i in range(len(masked_words)):
        if i > 0:
            result = result + " "
        result = result + masked_words[i]
    
    return result

def process_one_record(record_dict):
    # Process a single record
    
    # Copy the record so we can modify it
    result_dict = {}
    for key in record_dict:
        result_dict[key] = record_dict[key]
    
    # Check for standalone PII
    found_standalone_pii = False
    standalone_pii_list = []
    
    for field_name in record_dict:
        field_value = record_dict[field_name]
        
        # Check phone
        if check_if_phone(field_value, field_name):
            found_standalone_pii = True
            standalone_pii_list.append(("phone", field_name, field_value))
        
        # Check aadhaar  
        elif check_if_aadhaar(field_value):
            found_standalone_pii = True
            standalone_pii_list.append(("aadhaar", field_name, field_value))
        
        # Check passport
        elif check_if_passport(field_value, field_name):
            found_standalone_pii = True
            standalone_pii_list.append(("passport", field_name, field_value))
        
        # Check UPI
        elif check_if_upi(field_value):
            found_standalone_pii = True
            standalone_pii_list.append(("upi", field_name, field_value))
    
    # Check for combination PII
    has_name = False
    has_email = False
    has_complete_address = False
    has_device_info = False
    
    combination_pii_list = []
    
    # Check for name
    if "name" in record_dict:
        if check_if_full_name(record_dict["name"]):
            has_name = True
            combination_pii_list.append(("name", "name", record_dict["name"]))
    
    # Check for first + last name
    if "first_name" in record_dict and "last_name" in record_dict:
        first_name = str(record_dict["first_name"]).strip()
        last_name = str(record_dict["last_name"]).strip()
        if first_name != "" and last_name != "":
            has_name = True
            full_name = first_name + " " + last_name
            combination_pii_list.append(("name", "first_last", full_name))
    
    # Check for email
    for field_name in record_dict:
        field_value = record_dict[field_name]
        if check_if_email(field_value):
            has_email = True
            combination_pii_list.append(("email", field_name, field_value))
            break  # Only need one email
    
    # Check for complete address
    address_components = 0
    if "address" in record_dict:
        if str(record_dict["address"]).strip() != "":
            address_components = address_components + 1
    if "city" in record_dict:
        if str(record_dict["city"]).strip() != "":
            address_components = address_components + 1  
    if "pin_code" in record_dict:
        if str(record_dict["pin_code"]).strip() != "":
            address_components = address_components + 1
    
    if address_components >= 3:
        has_complete_address = True
        combination_pii_list.append(("address", "address", record_dict.get("address", "")))
    
    # Check for device info
    if "device_id" in record_dict:
        has_device_info = True
        combination_pii_list.append(("device", "device_id", record_dict["device_id"]))
    if "ip_address" in record_dict:
        has_device_info = True
        combination_pii_list.append(("device", "ip_address", record_dict["ip_address"]))
    
    # Count combination types
    combination_types = 0
    if has_name:
        combination_types = combination_types + 1
    if has_email:
        combination_types = combination_types + 1
    if has_complete_address:
        combination_types = combination_types + 1
    if has_device_info:
        combination_types = combination_types + 1
    
    # Determine if this record has PII
    is_pii_record = False
    if found_standalone_pii:
        is_pii_record = True
    if combination_types >= 2:
        is_pii_record = True
    
    # Apply masking for standalone PII
    for pii_info in standalone_pii_list:
        pii_type = pii_info[0]
        field_name = pii_info[1]
        field_value = pii_info[2]
        
        if pii_type == "phone":
            result_dict[field_name] = mask_phone_number(field_value)
        elif pii_type == "aadhaar":
            result_dict[field_name] = mask_aadhaar_number(field_value)
        elif pii_type == "passport":
            result_dict[field_name] = mask_passport_number(field_value)
        elif pii_type == "upi":
            result_dict[field_name] = mask_upi_id(field_value)
    
    # If record has PII, mask combination elements too
    if is_pii_record:
        for combo_info in combination_pii_list:
            combo_type = combo_info[0]
            field_name = combo_info[1]
            field_value = combo_info[2]
            
            if combo_type == "name":
                if field_name == "first_last":
                    # Mask both first_name and last_name
                    if "first_name" in result_dict:
                        result_dict["first_name"] = mask_name(result_dict["first_name"])
                    if "last_name" in result_dict:
                        result_dict["last_name"] = mask_name(result_dict["last_name"])
                else:
                    result_dict[field_name] = mask_name(field_value)
            
            elif combo_type == "email":
                result_dict[field_name] = mask_email_address(field_value)
            
            elif combo_type == "address":
                if "address" in result_dict:
                    result_dict["address"] = "HIDDEN_ADDRESS"
                if "city" in result_dict:
                    result_dict["city"] = "HIDDEN_CITY"
                if "pin_code" in result_dict:
                    pin_digits = extract_digits_only(result_dict["pin_code"])
                    if len(pin_digits) >= 2:
                        result_dict["pin_code"] = "XXXX" + pin_digits[-2] + pin_digits[-1]
                    else:
                        result_dict["pin_code"] = "XXXX"
            
            elif combo_type == "device":
                if field_name == "ip_address":
                    # Simple IP masking
                    ip_text = str(field_value)
                    if "." in ip_text:
                        # Split by dots
                        parts = []
                        current_part = ""
                        for char in ip_text:
                            if char == ".":
                                parts.append(current_part)
                                current_part = ""
                            else:
                                current_part = current_part + char
                        parts.append(current_part)
                        
                        if len(parts) == 4:
                            parts[3] = "XXX"
                            masked_ip = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
                            result_dict[field_name] = masked_ip
                        else:
                            result_dict[field_name] = "HIDDEN_IP"
                    else:
                        result_dict[field_name] = "HIDDEN_IP"
                else:
                    result_dict[field_name] = "HIDDEN_DEVICE"
    
    return result_dict, is_pii_record

# Main processing
print("Starting PII detection...")

# Open input file
try:
    input_file = open(input_filename, 'r', encoding='utf-8')
except:
    print("Error: Cannot open input file")
    sys.exit(1)

# Open output file
try:
    output_file = open(output_filename, 'w', encoding='utf-8', newline='')
except:
    print("Error: Cannot create output file")
    sys.exit(1)

# Read CSV
csv_reader = csv.DictReader(input_file)
csv_writer = csv.DictWriter(output_file, fieldnames=["record_id", "redacted_data_json", "is_pii"])
csv_writer.writeheader()

record_count = 0
pii_count = 0

# Process each row
for row in csv_reader:
    record_count = record_count + 1
    
    # Get record ID
    record_id = ""
    if "record_id" in row:
        record_id = row["record_id"]
    elif "id" in row:
        record_id = row["id"]
    
    # Get JSON data
    json_data = ""
    if "data_json" in row:
        json_data = row["data_json"]
    elif "Data_json" in row:
        json_data = row["Data_json"]
    
    # Parse JSON data
    try:
        parsed_data = json.loads(json_data)
    except:
        # Try to handle escaped quotes
        try:
            cleaned_data = json_data.strip()
            if cleaned_data.startswith('"') and cleaned_data.endswith('"'):
                cleaned_data = cleaned_data[1:-1]
            cleaned_data = cleaned_data.replace('""', '"')
            parsed_data = json.loads(cleaned_data)
        except:
            # Give up and use raw data
            parsed_data = {"raw_data": json_data}
    
    # Process this record
    masked_data, is_pii = process_one_record(parsed_data)
    
    if is_pii:
        pii_count = pii_count + 1
    
    # Convert result to JSON
    result_json = json.dumps(masked_data, ensure_ascii=False)
    
    # Write to output
    csv_writer.writerow({
        "record_id": record_id,
        "redacted_data_json": result_json,
        "is_pii": "True" if is_pii else "False"
    })

# Close files
input_file.close()
output_file.close()

print("[+] Wrote output:", output_filename)
print("Processed", record_count, "records")
print("Found", pii_count, "records with PII")
