import re
from urllib.parse import urlparse, urljoin, urldefrag
from urllib import robotparser
from collections import defaultdict
from bs4 import BeautifulSoup
from typing import List
import hashlib

visited_urls = set()
path_counts = defaultdict(int)
param_counts = defaultdict(int)
visited_page_hashes = set()
longest_page = ""
longest_page_word_count = 0
all_word_freqs = defaultdict(int)
subdomain_counts = defaultdict(int)

def scraper(url, resp):
    if resp.status != 200 or not resp.raw_response:
        return []
    try: 
        if not resp.raw_response.headers['Content-Type'].startswith('text/html'):
            print("caught a non html file")
            print(f'header: {resp.raw_response.headers["Content-Type"]}')
            return []
    except Exception as e:
        print(f"Error filtering for html pages {url}: {e}")
        return []


    defragged_url = urldefrag(resp.url)[0]
    if defragged_url in visited_urls:
        print("mistake - added duplicate site to frontier")
        return []

    visited_urls.add(defragged_url)

    try:
        content = resp.raw_response.content
        soup = BeautifulSoup(content, 'html.parser')
    except Exception as e:
        print(f"Error creating soup for {url}: {e}")
        return []
    
    if len(visited_urls) <= 5:
        analyze_text_content(resp, defragged_url, soup)
        links = extract_next_links(url, resp, soup)
        return [link for link in links if is_valid(link)]

    if process_page(resp, soup):
        analyze_text_content(resp, defragged_url, soup)
        links = extract_next_links(url, resp, soup)
        return [link for link in links if is_valid(link)]
    
    return []


def extract_next_links(url, resp, soup):
    links = []
    if resp.status != 200 or resp.raw_response is None:
        return links
        
    try:
        text_content = soup.get_text()
        tokens = tokenize(text_content)
        freqs_vector = hash_word_frequencies(tokens, 4096)   #can increase size of vocab if too many collisions
        freqs_vector = tuple(freqs_vector)

        if freqs_vector in visited_page_hashes:
            print("duplicate detected")
            return links

        for page_hash in visited_page_hashes:
            score = hashed_frequencies_difference(freqs_vector, page_hash, 4096)
            if score >= 0.99:                              #can adjust this threshold
                print("found dup or near-dup")
                return links

        visited_page_hashes.add(freqs_vector)

        for anchor in soup.find_all('a', href=True):
            href = anchor['href']
            full_url = urljoin(url, href)
            defragmented_url, _ = urldefrag(full_url)
            if is_trap(defragmented_url, visited_urls, path_counts):
                continue
            links.append(defragmented_url)

    except Exception as e:
        print(f"[extract_next_links] Error parsing {url}: {e}")
    
    return links

def analyze_text_content(resp, url, soup):
    global longest_page, longest_page_word_count, all_word_freqs, subdomain_counts

    try:
        text_content = soup.get_text()
        tokens = tokenize(text_content)
        word_count = len(tokens)

        if word_count > longest_page_word_count:
            longest_page = url
            longest_page_word_count = word_count

        word_freqs = computeWordFrequencies(tokens)
        stop_words = get_stop_words()
        filtered_word_freqs = {word: freq for word, freq in word_freqs.items()
                               if word.lower() not in stop_words}

        for word, freq in filtered_word_freqs.items():
            all_word_freqs[word] += freq

        parsed_url = urlparse(url)
        subdomain = parsed_url.netloc
        subdomain_counts[subdomain] += 1
        return word_count, filtered_word_freqs, subdomain

    except Exception as e:
        print(f"Error analyzing content from {url}: {e}")
        return 0, {}, ""

def process_page(resp, soup):
    max_size = 1024 * 1024
    min_text_ratio = 0.02
    min_tokens = 80

    try:
        content = resp.raw_response.content
        content_size = len(content)
        
        #content = ""
        #content_size = 0
        #if resp.raw_response.headers['Content-Length']:
        #    content_size = int(resp.raw_response.headers['Content-Length'])
        #else:
        #    content = resp.raw_response.content
        #    content_size = len(content)

        if content_size > max_size:
            print(f"Skipping large file: {resp.url} ({content_size} bytes)")
            return False

        text_content = soup.get_text()
        #text_size = len(text_content)
        #text_ratio = text_size / content_size if content_size > 0 else 0
        tokens = tokenize(text_content)
        token_count = len(tokens)

        if token_count < min_tokens:
            print(f"Skipping low information page: tokens: {token_count})")
            return False
        
        return True

    except Exception as e:
        print(f"Error checking page quality: {e}")
        return True

def is_trap(url, visited_urls=set(), path_counts={}, max_visits=50, max_depth=10):
    if url in visited_urls:
        return True

    parsed = urlparse(url)
    segments = [s for s in parsed.path.split('/') if s]

    if len(segments) > max_depth:
        return True

    simplified = '/'.join(['N' if s.isdigit() else s for s in segments])
    path_counts[simplified] = path_counts.get(simplified, 0) + 1
    if path_counts[simplified] > max_visits:
        return True

    return False

def get_stop_words():
    return {
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
        "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
        "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't",
        "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
        "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
        "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
        "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
        "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's",
        "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself", "no",
        "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our",
        "ours", "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd",
        "she'll", "she's", "should", "shouldn't", "so", "some", "such", "than", "that",
        "that's", "the", "their", "theirs", "them", "themselves", "then", "there",
        "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this",
        "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't",
        "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's",
        "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom",
        "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll",
        "you're", "you've", "your", "yours", "yourself", "yourselves"
    }

def is_valid(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        allowed_domains = [
            ".ics.uci.edu",
            ".cs.uci.edu",
            ".informatics.uci.edu",
            ".stat.uci.edu",
            "today.uci.edu/department/information_computer_sciences"
        ]
        blocked_domains = [
            "sli.ics.uci.edu",
        ]

        blocked_paths = [
            "/doku.php",
            "/~seal/projects"
        ]
            
        is_allowed = any(parsed.netloc.endswith(domain) for domain in allowed_domains)

        if not is_allowed and parsed.netloc == "today.uci.edu":
            if "/department/information_computer_sciences" in parsed.path:
                is_allowed = True

        if not is_allowed:
            return False
        

       # if "/~seal/projects" in parsed.path:
       #     print(f"Blocked a url under /~seal/projects")
       #     return False
       
        for blocked in blocked_domains:
            if parsed.netloc.endswith(blocked):
                print(f'Blocked a url under {blocked} subdomain')
                return False


        for blocked in blocked_paths:
            if parsed.path.startswith(blocked):
                print(f'Blocked a url under {blocked} path')
                return False

        if len(url) > 200:
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4|mpg"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower()
        )

    except TypeError:
        print("TypeError for ", parsed)
        raise

def hashed_frequencies_difference(vecA: list[float], vecB: list[float], size: int) -> float:
    '''
    Takes two token frequency vectors for two pages, and similarity scores them (1 being the "same").

    Args:
        vecA (list[float]): token frequency list for document A
        vecB (list[float]): token frequency list for document B
        size (int): size of vector

    Returns:
        float: normalized difference between two documents (1 being the same) 
    '''    
    num_words_a = sum(vecA)
    num_words_b = sum(vecB)

    #handle if both are empty, or either is empty 
    if num_words_a == 0 and num_words_b == 0:
        return 1.0
    elif num_words_a == 0 or num_words_b == 0:
        return 0.0 

    #compute frequency of each word in its document, and compares frequencies between the 2 documents
    differences = []
    for item in range(size):
        freqA = vecA[item] / num_words_a
        freqB = vecB[item] / num_words_b
        differences.append(abs(freqA - freqB))
        
    #sum differences in relative frequencies for all words --> gives percent similarity, with 1 being exactly the same
    return 1 - (sum(differences) / 2) 

def hash_word_frequencies(tokens: List[str], size: int=4096) -> list[float]:
    '''
    Cleans up token list, hashes them, and increments list[token] to represent token frequencies.
    '''
    stopwords = get_stop_words()
    
    list_freqs = [0.0] * size
    for token in tokens:
        if token not in stopwords:
            hash_bytes = hashlib.sha1(token.encode('utf-8')).digest()
            hash_int = int.from_bytes(hash_bytes[:4], byteorder='big')
            hashed_token_index = hash_int % size
            list_freqs[hashed_token_index] += 1
    return list_freqs
            
def tokenize(text: str) -> List[str]:
    tokens = []
    valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

    token = ''
    for char in text:
        if char in valid_chars:
            token += char
        else:
            if token != '':
                tokens.append(token.lower())
                token = ''

    if token != '':
        tokens.append(token.lower())

    return tokens

def computeWordFrequencies(token_list: List) -> dict[str, int]:
    dict_frequencies = {}
    for token in token_list:
        uncased_token = token.lower()
        if uncased_token in dict_frequencies:
            dict_frequencies[uncased_token] += 1
        else:
            dict_frequencies[uncased_token] = 1
    return dict_frequencies

def count_unique_pages_and_subdomains():
    unique_page_count = len(visited_urls)
    return unique_page_count, subdomain_counts

def print_report():
    global longest_page, longest_page_word_count, all_word_freqs
    unique_page_count, subdomain_data = count_unique_pages_and_subdomains()

    sorted_words = sorted(all_word_freqs.items(), key=lambda x: x[1], reverse=True)
    common_words = sorted_words[:50]
    sorted_subdomains = sorted(subdomain_data.items(), key=lambda x: x[0])

    try: 
        with open("report.txt", "w", encoding="utf-8") as f:
            f.write("\n CRAWLER REPORT \n")
            f.write(f"Total unique pages found: {unique_page_count}\n")
            f.write(f"\nLongest page: {longest_page}\n")
            f.write(f"Word count: {longest_page_word_count}\n")
        
            f.write("\nTop 50 most common words:\n")
            for word, freq in common_words:
                f.write(f"{word}: {freq}\n")
        
            f.write("\nSubdomains found:\n")
            for subdomain, count in sorted_subdomains:
                f.write(f"{subdomain}, {count}\n")

    except Exception as e: 
        print(f"Error writing report: {e}")

    print("\n CRAWLER REPORT \n")
    print(f"Total unique pages found: {unique_page_count}")
    print(f"\nLongest page: {longest_page}")
    print(f"Word count: {longest_page_word_count}")

    print("\nTop 50 most common words:")
    for word, freq in common_words:
        print(f"{word}: {freq}")

    print("\nSubdomains found:")
    for subdomain, count in sorted_subdomains:
        print(f"{subdomain}, {count}")
