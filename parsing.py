from gevent import monkey as curious_george

curious_george.patch_all(thread=False, select=False)
import sys
#sys.path.append('/Users/kirillkapustin/Documents/Python/shared-master')
import grequests
import re
import time
import requests
import pandas as pd
import sqlalchemy as sa
from xml.etree import ElementTree
from datetime import datetime, timedelta
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import logging


def parsing_citilink():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d - [%(levelname)s] %(name)s [%(module)s.%(funcName)s:%(lineno)d]: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.propagate = False

    # engine_pricemonitoring_analytics_conn_string = f"mysql+pymysql://{user}:{password}@{ip_base}/{schema}"

    parsingMoment = datetime.now()
    logger.info(f'parsingMoment:{parsingMoment}\n')

    def execute_sql_safe(query, engine, query_name, tries=1, sleep_seconds=10, enable_logs=True):
        """
        Функция для безопасного sql execute. Аргументы аналогичны функции read_sql_safe
        """
        sql_flag = False
        q = 0
        # df = None
        while not sql_flag:
            try:
                logger.warning(f'Начинаю execute {query_name}')
                engine.execution_options(autocommit=True).execute(query)
                logger.warning(f'Закончил execute {query_name}')
                sql_flag = True
                engine.dispose()
            except sa.exc.SQLAlchemyError:
                engine.dispose()
                sql_flag = False
                q += 1
                if q >= tries:
                    if enable_logs:
                        logger.warning(
                            f"Выполнение sql запроса выполнено с ошибкой. Попытки закончились, rais'им ошибку")
                    raise
                else:
                    if enable_logs:
                        logger.warning(
                            f'Выполнение sql запроса выполнено с ошибкой. жду {sleep_seconds} сек. и пробую снова')
                    sleep(sleep_seconds)
            # если ошибка не sql, то диспоузим коннекшн и рейзим ошибку
            except Exception as e:
                logger.error(e)
                engine.dispose()
                raise

    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6,zh;q=0.5',
        'cookie': 'old_design=1;'
    }
    error_counter = 0
    while True:
        try:
            sitemap_raw = requests.get('https://www.citilink.ru/sitemap/main/sitemap.xml', headers=headers)
            if sitemap_raw.status_code == 200: break
        except Exception as e:
            error_counter += 1
            if error_counter > 10: raise Exception()
            logger.error(f'EXCEPTION | {str(e)} | error_counter:{error_counter} | {time.sleep(10)}')

    sitemap_product_urls = [i[0].text for i in ElementTree.fromstring(sitemap_raw.content) if
                            re.search(r'main/products_\d+.xml', i[0].text)]
    if not sitemap_product_urls:
        logger.info(f'ALERT(!) | if not sitemap_product_urls')
        sitemap_product_urls = [
            'https://www.citilink.ru/sitemap/main/products_0.xml',
            'https://www.citilink.ru/sitemap/main/products_1.xml',
            'https://www.citilink.ru/sitemap/main/products_2.xml',
            'https://www.citilink.ru/sitemap/main/products_3.xml',
            'https://www.citilink.ru/sitemap/main/products_4.xml',
            'https://www.citilink.ru/sitemap/main/products_5.xml',
            'https://www.citilink.ru/sitemap/main/products_6.xml',
            'https://www.citilink.ru/sitemap/main/products_7.xml',
            'https://www.citilink.ru/sitemap/main/products_8.xml'
        ]
    logger.info(f'sitemap_product_urls:{len(sitemap_product_urls)}\n')

    loop_counter = 0
    error_counter = 0
    sitemap_skus_store = []
    for url in sitemap_product_urls:
        loop_counter = loop_counter + 1
        try:
            r = requests.get(url, headers=headers)
            product_urls = [i[1] for i in [re.search(r'www.citilink.ru/product/.+-(\d+)/$', i[0].text) for i in
                                           ElementTree.fromstring(r.content)] if i]
            sitemap_skus_store.extend(product_urls)
            time.sleep(1.2)
            if not loop_counter % 1: logger.info(
                f'sitemap_product_urls | loop_counter:{loop_counter} | error_counter:{error_counter} | sitemap_skus_store:{len(sitemap_skus_store)}')
        except Exception as e:
            error_counter = error_counter + 1
            if not error_counter % 10: logger.error(
                f'sitemap_product_urls | exception:{str(e)} | error_counter:{error_counter}')
            if error_counter > 30: raise Exception(f'exception:{str(e)} | error_counter:{error_counter}')
            sitemap_product_urls.append(url)
            time.sleep(5)
    logger.info(
        f'DONE | loop_counter:{loop_counter} | error_counter:{error_counter} | sitemap_skus_store:{len(sitemap_skus_store)}\n')

    def transfor_response_values(values):
        return [{
            'sku': v['id'],
            'name': v['name'],
            'isAvailable': v['isAvailable'],
            'stock_quantity': sum([i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities']]),
            'brandName': v['brandName'],
            'categoryName': v['categoryName'],
            'price': v['price'] * v['multiplicity'],
            'oldPrice': v['oldPrice'],
            'url': v['url'],
            'hasDiffColors': v['hasDiffColors'],
            'isCashCarry': v['isCashCarry'],
            'isAction': v['isAction'],
            'isActive': v['isActive'],
            'isDiscounted': v['isDiscounted'],
            'countReviews': v['countReviews'],
            'clubPrice': v['clubPrice'],
            'oldClubPrice': v['oldClubPrice'],
            'brandId': v['brandId'],
            'rating': v['rating'],
            'totalOpinion': v['totalOpinion'],
            'bonus': v['bonus'],
            'productGroupId': v['productGroupId'],
            'categoryId': v['categoryId'],
            'isHidden': v['isHidden'],
            'hasOffer': v['hasOffer'],
            'hasMarketingStatus': v['hasMarketingStatus'],
            'isVirtual': v['isVirtual'],
            'countAccs': v['countAccs'],
            'countDisc': v['countDisc'],
            'isRussiaDeliveryPossible': v['isRussiaDeliveryPossible'],
            'stock_quantity_type1': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 1]),
            'stock_quantity_type2': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 2]),
            'stock_quantity_type3': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 3]),
            'stock_quantity_type4': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 4]),
            'stock_quantity_type5': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 5]),
            'stock_quantity_type6': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 6]),
            'stock_quantity_type7': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 7]),
            'stock_quantity_type8': sum(
                [i['countOfAvailableItems'] or 0 for i in v['stocksSummary']['stockAvailabilities'] if
                 i['stock']['type'] == 8]),
            'multiplicity': v['multiplicity'],
        } for v in values]

    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
    }

    n = 20
    set_skus_store = list(set(sitemap_skus_store))
    set_skus_store_chunks = [set_skus_store[i:i + n] for i in range(0, len(set_skus_store), n)]

    concurrency = 10
    set_skus_store_chunks_concurrency_batch = [set_skus_store_chunks[i:i + concurrency] for i in
                                               range(0, len(set_skus_store_chunks), concurrency)]
    logger.info(
        f'set_skus_store:{len(set_skus_store)} | set_skus_store_chunks:{len(set_skus_store_chunks)} | set_skus_store_chunks_concurrency_batch:{len(set_skus_store_chunks_concurrency_batch)}')

    loop_counter = 0
    error_counter = 0
    result_store = []
    retry_tmp_batch = []

    def exception_handlerr(request, exception):
        global concurrency
        global error_counter
        error_counter += 1
        if error_counter > 5500: raise Exception()
        if not error_counter % 250:
            logger.error(
                f'EXCEPTION | {str(exception).split("(")[0]} | loop_counter:{loop_counter} | error_counter:{error_counter} | result_store:{len(result_store)}')

        if len(retry_tmp_batch) < concurrency:
            retry_tmp_batch.append(request.url.split('=')[1].split(','))
        if len(retry_tmp_batch) >= concurrency:
            set_skus_store_chunks_concurrency_batch.append(retry_tmp_batch[:])
            retry_tmp_batch.clear()

    for batch in set_skus_store_chunks_concurrency_batch:
        rs = [grequests.get(f'https://www.citilink.ru/promo/getgoods/?ids={",".join(u)}', headers=headers, timeout=4,
                            verify=False) for u in batch]
        for r in grequests.map(rs, exception_handler=exception_handlerr):
            loop_counter = loop_counter + 1
            if r and r.json():
                result_store.extend(transfor_response_values(r.json().values()))
        if not loop_counter % 200: logger.info(
            f'LOG | loop_counter:{loop_counter} | error_counter:{error_counter} | result_store:{len(result_store)}')
    logger.info(
        f'MAIN LOOP | result_store:{len(result_store)} | error_counter:{error_counter} | retry_tmp_batch:{len(retry_tmp_batch)}\n')

    loop_counter = 0
    error_counter = 0
    for chunk in retry_tmp_batch:
        loop_counter = loop_counter + 1
        url = f'https://www.citilink.ru/promo/getgoods/?ids={",".join(chunk)}'
        try:
            values = requests.get(url, headers=headers, verify=False, timeout=4).json().values()
            result_store.extend(transfor_response_values(values))
            if not loop_counter % 1: logger.info(
                f'LOG | loop_counter:{loop_counter} | error_counter:{error_counter} | result_store:{len(result_store)}')
        except Exception as e:
            error_counter = error_counter + 1
            logger.error(
                f'EXCEPTION | {str(e).split("(")[0]} | loop_counter:{loop_counter} | error_counter:{error_counter} | result_store:{len(result_store)}')
            if error_counter > 20: raise Exception()
            retry_tmp_batch.append(chunk)
    logger.info(
        f'FULL COMPLETED | loop_counter:{loop_counter} | error_counter:{error_counter} | result_store:{len(result_store)}\n')
    return result_store

if __name__ == "__main__":
    df_ready_to_insert = pd.DataFrame.from_dict(result_store, orient='columns')
    df_ready_to_insert = df_ready_to_insert.replace(r'[\t\n\r;]+', ' ', regex=True).replace(r'\\', '/', regex=True).replace(
        r'\s+', ' ', regex=True).replace('(^\s+|\s+$)', '', regex=True).replace('("+|«|»)', '"', regex=True)
    df_ready_to_insert.insert(0, 'parsingMoment', parsingMoment)

    ip_base = '192.168.1.99'  # ip базы куда запысываем - так как он динамический приходится менять
    user = 'kirill'  # юзер в БД
    password = '110977'  # пароль от БД
    schema = 'dhawk_database'  # Схема в БД
    name = 'citilink_parse_remains_stat'

    df_ready_to_insert.to_sql(
        name=DESTINATION_TABLE_NAME,
        schema=DESTINATION_SCHEMA_NAME,
        con=engine_pricemonitoring_analytics_conn_string,
        index=False,
        if_exists='replace')