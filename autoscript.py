import requests
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MultiChainAutomation:
    def __init__(self, chains):
        self.chains = chains
        self.mining_threads = {}
        self.stop_mining = {}
        self.node_check_interval = 300
        self.max_retries = 3
        self.retry_delay = 5

    def mine_continuously(self, chain_url):
        retries = 0
        while not self.stop_mining.get(chain_url, False):
            try:
                response = requests.get(f"{chain_url}/mine_block", timeout=25)
                response.raise_for_status()
                block_data = response.json()
                block_time = block_data.get('block_time', 0)
                logging.info(f"Mined a block on {chain_url} in {block_time:.2f} seconds")
                
                # Apply consensus after mining a block
                self.apply_consensus(chain_url)
                
                retries = 0
            except requests.RequestException as e:
                logging.error(f"Failed to mine a block on {chain_url}: {str(e)}")
                retries += 1
                if retries > self.max_retries:
                    logging.error(f"Max retries exceeded for {chain_url}. Stopping mining on this chain.")
                    self.stop_mining_on_chain(chain_url)
                    break
                time.sleep(self.retry_delay)

    def apply_consensus(self, chain_url):
        try:
            response = requests.get(f"{chain_url}/apply_consensus", timeout=10)
            response.raise_for_status()
            result = response.json()
            if 'message' in result:
                if "chain was replaced" in result['message']:
                    logging.info(f"Consensus applied on {chain_url}: {result['message']}")
                else:
                    logging.info(f"No consensus changes needed on {chain_url}: {result['message']}")
            else:
                logging.warning(f"Unexpected response from {chain_url}: {result}")
        except requests.RequestException as e:
            logging.error(f"Failed to apply consensus on {chain_url}: {str(e)}")

    def start_mining(self, chain_url):
        if chain_url not in self.mining_threads:
            self.stop_mining[chain_url] = False
            thread = threading.Thread(target=self.mine_continuously, args=(chain_url,))
            thread.start()
            self.mining_threads[chain_url] = thread
            logging.info(f"Started mining on {chain_url}")

    def stop_mining_on_chain(self, chain_url):
        if chain_url in self.mining_threads:
            self.stop_mining[chain_url] = True
            self.mining_threads[chain_url].join()
            del self.mining_threads[chain_url]
            logging.info(f"Stopped mining on {chain_url}")

    def check_chain_health(self, chain_url):
        try:
            response = requests.get(f"{chain_url}/get_chain", timeout=5)
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def manage_chains(self):
        while True:
            for chain in list(self.chains):
                if not self.check_chain_health(chain):
                    logging.warning(f"Chain {chain} is unhealthy. Stopping mining and removing from chain list.")
                    self.stop_mining_on_chain(chain)
                    self.chains.remove(chain)
            time.sleep(self.node_check_interval)

    def run(self):
        logging.info("Starting automatic mining on all chains...")
        for chain in self.chains:
            self.start_mining(chain)

        chain_management_thread = threading.Thread(target=self.manage_chains)
        chain_management_thread.daemon = True
        chain_management_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Stopping all mining operations...")
            for chain_url in list(self.mining_threads.keys()):
                self.stop_mining_on_chain(chain_url)

if __name__ == "__main__":
    try:
        with open('nodes.json', 'r') as f:
            nodes_data = json.load(f)
        nodes = nodes_data['nodes']
        automation = MultiChainAutomation(nodes)
        automation.run()
    except FileNotFoundError:
        logging.error("nodes.json file not found. Please create a JSON file with a list of chain URLs.")
    except json.JSONDecodeError:
        logging.error("Error parsing chains.json. Please ensure it's a valid JSON file.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")