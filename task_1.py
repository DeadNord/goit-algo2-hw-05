import logging
from colorama import init, Fore
from typing import List, Dict

# =====================
# Initialize colorama and logger
# =====================
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class BloomFilter:
    """
    Simple Bloom Filter implementation using a bit array.
    We rely on multiple hash attempts to set/check bits.
    """

    def __init__(self, size: int, num_hashes: int):
        """
        :param size: number of bits in the Bloom Filter.
        :param num_hashes: how many different hash functions to use.
        """
        logger.info(
            Fore.CYAN
            + f"Initializing BloomFilter with size={size}, num_hashes={num_hashes}"
        )
        self.size = size
        self.num_hashes = num_hashes

        # We'll use a bytearray to store bits => size//8 + 1 bytes
        self.bit_array = bytearray((size + 7) // 8)

    def _set_bit(self, index: int):
        """
        Set the bit at 'index' to 1.
        """
        byte_index = index // 8
        bit_index = index % 8
        self.bit_array[byte_index] |= 1 << bit_index

    def _get_bit(self, index: int) -> bool:
        """
        Check if the bit at 'index' is 1.
        """
        byte_index = index // 8
        bit_index = index % 8
        return (self.bit_array[byte_index] & (1 << bit_index)) != 0

    def _hashes(self, item: str):
        """
        Generate 'num_hashes' different hash values for 'item'.
        We'll vary a salt each time so that we get different results from Python's hash().
        """

        for i in range(self.num_hashes):
            # combine the base hash(item) with a "salt"
            salted = f"{i}-{item}"
            h = hash(salted)
            yield h % self.size

    def add(self, item: str):
        """
        Add an item (password) to the Bloom Filter.
        """
        if not isinstance(item, str):
            logger.error(Fore.RED + f"add(...) error: item must be a string. Skipping.")
            return

        # Generate each hash, set the corresponding bit
        for idx in self._hashes(item):
            self._set_bit(idx)

    def contains(self, item: str) -> bool:
        """
        Check if item (password) might be in the filter (False Positives are possible).
        Return True if it might be in the filter, False if definitely not.
        """
        if not isinstance(item, str):
            logger.error(
                Fore.RED
                + f"contains(...) error: item must be a string. Returning False."
            )
            return False

        for idx in self._hashes(item):
            if not self._get_bit(idx):
                return False
        return True


def check_password_uniqueness(
    bloom_filter: BloomFilter, new_passwords: List[str]
) -> Dict[str, str]:
    """
    This function checks if each password in 'new_passwords' was used before
    (via the BloomFilter).

    :param bloom_filter: instance of BloomFilter
    :param new_passwords: list of passwords to check
    :return: dict {password: "вже використаний" or "унікальний"}
    """
    logger.info(
        Fore.CYAN + f"Checking uniqueness for {len(new_passwords)} new passwords..."
    )
    results = {}
    for pwd in new_passwords:
        # Handle incorrectly typed data
        if not isinstance(pwd, str):
            logger.warning(
                Fore.YELLOW
                + f"Invalid password type: {pwd}. Marking as 'унікальний' by default."
            )
            results[str(pwd)] = "унікальний"
            continue

        # check if it might be in filter
        if bloom_filter.contains(pwd):
            results[pwd] = "вже використаний"
        else:
            results[pwd] = "унікальний"

    return results


def main():
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        logger.info(Fore.GREEN + f"Adding existing password: {password}")
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")


if __name__ == "__main__":
    main()
