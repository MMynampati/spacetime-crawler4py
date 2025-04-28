import re
from urllib.parse import urlparse, urljoin, urldefrag
from urllib import robotparser
from collections import defaultdict
from bs4 import BeautifulSoup
from typing import List


visited_urls = set()
path_counts = defaultdict(int)
param_counts = defaultdict(int)


def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    links = []
    if resp.status != 200 or resp.raw_response is None:
        return links
    
    try:
        content = resp.raw_response.content
        soup = BeautifulSoup(content, 'html.parser')
        #word_count, filtered_words = analyze_text_content(content)

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

def analyze_text_content(content):
    pass
    #return tokenize(content,) 


def is_trap(url, visited_urls=set(), path_counts={}, max_visits=30, max_depth=8):
    if url in visited_urls:
        return True
    visited_urls.add(url)
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split('/') if s]

    if len(segments) > max_depth:
        return True

    # Normalize numeric parts to catch /page/1, /page/2
    simplified = '/'.join(['N' if s.isdigit() else s for s in segments])
    path_counts[simplified] = path_counts.get(simplified, 0) + 1
    if path_counts[simplified] > max_visits:
        return True

    return False
    
    
def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
            
        # Check if the URL is within the domains we want to crawl
        allowed_domains = [
            ".ics.uci.edu",
            ".cs.uci.edu",
            ".informatics.uci.edu",
            ".stat.uci.edu",
            "today.uci.edu/department/information_computer_sciences"
        ]
        
        is_allowed = any(parsed.netloc.endswith(domain) for domain in allowed_domains)
        
        if not is_allowed and parsed.netloc == "today.uci.edu":
            if "/department/information_computer_sciences" in parsed.path:
                is_allowed = True
                
        if not is_allowed:
            return False
            
        if len(url) > 200:
            return False


        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

def normalized_word_frequencies_difference(dictA: dict[str, int], dictB: dict[str, int]) -> float:
    '''
    Takes two token frequency dictionaries for two pages, and similarity scores them (1 being the "same").
    Compares the differences in word frequencies between the two dictionaries, and normalizes them by the total 
    number of words to attempt to account for (potential) different document sizes.

    Args:
        dictA (dict[str,int]): token frequency map for document A
        dictB (dict[str,int]): token frequency map for document B

    Returns:
        float: normalized difference between two documents (1 being the same) 
    '''
    ##NOTES: MIGHT NEED TO OPTIMIZE FOR LARGE DICTS 
        #better data structures for storage ?
        #stopword filtering? 
    
    num_words_a = sum(dictA.values())
    num_words_b = sum(dictB.values())

    #handle if both are empty, or either is empty 
    if num_words_a == 0 and num_words_b == 0:
        return 1.0
    elif num_words_a == 0 or num_words_b == 0:
        return 0.0 

    all_words = set(dictA) | set(dictB)

    #compute frequency of each word in its document, and compares frequencies between the 2 documents
    differences = []
    for word in all_words:
        frequency_in_A = dictA.get(word, 0) / num_words_a
        frequency_in_B = dictB.get(word, 0) / num_words_b
        differences.append(abs(frequency_in_A - frequency_in_B))
        
    #sum differences in relative frequencies for all words --> gives percent similarity, with 1 being exactly the same
    return (1 - sum(differences) / 2) 


def tokenize(text: str) -> List[str]:
    '''
    Reads in a string and returns a list of tokens.
    Valid tokens are sequences of alphanumeric chars, regardless of capitalization.

    Args:
        text (str): text string 
    
    Returns:
        List[str]: list of tokens
    '''
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
    
    #check for last token 
    if token != '':
        tokens.append(token.lower())

    return tokens

def computeWordFrequencies(token_list: List) -> dict[str, int]:
    '''
    Counts number of occurences of each token in the list.
    Runtime Complexity: O(n), n being the number of tokens in the list 

    Args:
        token_list (List): list of cased tokens

    Returns:
        Dict[str, int]: dict of uncased tokens and their associated frequencies
        
    '''

    dict_frequencies = {}
    for token in token_list:
        uncased_token = token.lower()
        if uncased_token in dict_frequencies:
            dict_frequencies[uncased_token] += 1
        else:
            dict_frequencies[uncased_token] = 1
    
    return dict_frequencies
