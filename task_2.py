import logging
import re
import time

from colorama import init, Fore
from tabulate import tabulate

# Імпортуємо HyperLogLog і HyperLogLogPlusPlus із datasketch
from datasketch import HyperLogLog, HyperLogLogPlusPlus

# ===============================
# Initialize colorama and logger
# ===============================
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class LogParser:
    """
    Class to parse a log file and extract IP addresses.
    Ignores invalid lines or lines without a valid IP.
    """

    # Простий шаблон для IPv4:
    IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    def __init__(self, filepath: str):
        self.filepath = filepath

    def load_ips(self):
        """
        Loads the log file, extracts IP addresses from each line.
        Returns a list of IP strings.
        Ignores lines that don't contain a valid IPv4.
        """
        logger.info(Fore.CYAN + f"Loading log file: {self.filepath}")
        ips = []
        line_num = 0
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, start=1):
                    match = self.IP_REGEX.search(line)
                    if match:
                        ip = match.group(0)
                        ips.append(ip)
                    else:
                        # Якщо рядок не містить валідної IP
                        logger.debug(
                            Fore.YELLOW
                            + f"Line {line_num}: No valid IP found. Skipping."
                        )
        except FileNotFoundError:
            logger.error(Fore.RED + f"File not found: {self.filepath}")
            return []
        except Exception as e:
            logger.error(Fore.RED + f"Error reading file: {e}")
            return []

        logger.info(
            Fore.GREEN + f"Total lines read: {line_num}, IPs extracted: {len(ips)}"
        )
        return ips


def exact_count_unique_ips(ips):
    """
    Returns the exact number of unique IP addresses using a set.
    """
    logger.info(Fore.BLUE + "Starting exact count of unique IPs...")
    return len(set(ips))


def approximate_count_unique_ips_hll(ips, p=16):
    """
    Uses HyperLogLog from datasketch to approximate the count of unique IPs.

    :param p: Precision parameter for HLL. Range typically [4..16] for datasketch HyperLogLog.
    """
    logger.info(Fore.BLUE + f"Starting approximate HLL count (HyperLogLog) with p={p}.")
    hll = HyperLogLog(p=p)
    for ip in ips:
        hll.update(ip.encode("utf-8", errors="replace"))
    return hll.count()


def approximate_count_unique_ips_hll_plus(ips, p=16):
    """
    Uses HyperLogLogPlusPlus from datasketch to approximate the count of unique IPs.

    :param p: Precision parameter for HLL++. Range typically [4..16].
    """
    logger.info(
        Fore.BLUE
        + f"Starting approximate HLL++ count (HyperLogLogPlusPlus) with p={p}."
    )
    hllpp = HyperLogLogPlusPlus(p=p)
    for ip in ips:
        hllpp.update(ip.encode("utf-8", errors="replace"))
    return hllpp.count()


def compare_methods(ips, p=16):
    """
    Compare time and results of:
      1) exact_count_unique_ips (set)
      2) approximate_count_unique_ips_hll (HyperLogLog)
      3) approximate_count_unique_ips_hll_plus (HyperLogLogPlusPlus)

    Returns a dict with:
      {
        'exact_count': ..., 'exact_time': ...,
        'hll_count': ..., 'hll_time': ...,
        'hllpp_count': ..., 'hllpp_time': ...
      }
    """

    # 1) Exact method
    start = time.time()
    exact_result = exact_count_unique_ips(ips)
    exact_time = time.time() - start

    # 2) HLL
    start = time.time()
    hll_result = approximate_count_unique_ips_hll(ips, p=p)
    hll_time = time.time() - start

    # 3) HLL++
    start = time.time()
    hllpp_result = approximate_count_unique_ips_hll_plus(ips, p=p)
    hllpp_time = time.time() - start

    return {
        "exact_count": exact_result,
        "exact_time": exact_time,
        "hll_count": hll_result,
        "hll_time": hll_time,
        "hllpp_count": hllpp_result,
        "hllpp_time": hllpp_time,
    }


def main():
    logger.info(
        Fore.CYAN + "=== Starting HyperLogLog vs Exact Count Demo (datasketch) ==="
    )

    # Задаємо шлях до лог-файлу з IP-адресами
    file_path = "lms-stage-access.log"
    parser = LogParser(file_path)
    ips = parser.load_ips()
    if not ips:
        logger.warning(Fore.RED + "No IPs loaded. Exiting.")
        return

    # Змінна p (precision). В datasketch HyperLogLog(PlusPlus) дозволяє [4..16].
    p_value = 16
    results = compare_methods(ips, p=p_value)

    # Формуємо та виводимо таблицю з 3-ма методами
    table_data = [
        [
            "Унікальні елементи",
            f"{results['exact_count']}",
            f"{results['hll_count']:.2f}",
            f"{results['hllpp_count']:.2f}",
        ],
        [
            "Час виконання (сек.)",
            f"{results['exact_time']:.4f}",
            f"{results['hll_time']:.4f}",
            f"{results['hllpp_time']:.4f}",
        ],
    ]

    print("Результати порівняння:")
    print(
        tabulate(
            table_data,
            headers=["", "Точний підрахунок", "HyperLogLog", "HyperLogLog++"],
            tablefmt="github",
        )
    )


if __name__ == "__main__":
    main()
