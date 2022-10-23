import asyncio
import logging
import os
import traceback
from asyncio import Lock, sleep
from functools import partial

import aiofiles
import pandas
from aiohttp import web
from nfstream import NFStreamer
from sqlalchemy import create_engine

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise KeyboardInterrupt("Not env var DATABASE_URL!")
engine = create_engine(DATABASE_URL)


nfstream_create = partial(
    NFStreamer,
    source="to_analyse.pcap",
    decode_tunnels=True,
    bpf_filter=None,
    promiscuous_mode=True,
    snapshot_length=1536,
    idle_timeout=120,
    active_timeout=1800,
    accounting_mode=1,
    udps=None,
    n_dissections=20,
    statistical_analysis=False,
    splt_analysis=0,
    n_meters=0,
    performance_report=0,
)


NDPI_TIME = 30  # sec
pcap_file_lock = Lock()
logger = logging.Logger(__name__)


async def capture_pcap(request):

    async with pcap_file_lock, aiofiles.open("packets.pcap", "a+b") as out:
        await out.write(await request.read())
        await out.flush()
    return web.Response(text="success")


async def background_tasks(app):
    analyse_task = asyncio.create_task(analyse())
    yield
    await analyse_task


async def analyse():
    # FIXME move analyser to subprocess
    while True:
        async with pcap_file_lock:
            try:
                if os.path.exists("packets.pcap"):
                    os.rename("packets.pcap", "to_analyse.pcap")
                    package_streamer = nfstream_create()
                    package_df = package_streamer.to_pandas(columns_to_anonymize=[])
                    load_to_db(package_df)
            except Exception as e:
                logger.error(
                    f"Error while parse pcap and load to db {e!r}\n{traceback.format_exc()}"
                )
            finally:
                try:
                    os.remove("to_analyse.pcap")
                except:
                    ...
        await sleep(NDPI_TIME)


def main():
    app = web.Application(client_max_size=None)
    app.add_routes([web.post("/", capture_pcap)])
    app.cleanup_ctx.append(background_tasks)
    web.run_app(app)


def load_to_db(package_df: pandas.DataFrame):
    package_df.drop(
        [
            "bidirectional_first_seen_ms",
            "src2dst_first_seen_ms",
            "src2dst_first_seen_ms",
            "src2dst_last_seen_ms",
            "dst2src_first_seen_ms",
            "dst2src_last_seen_ms",
            "dst2src_duration_ms",
            "src2dst_duration_ms",
            "bidirectional_duration_ms",
            "bidirectional_last_seen_ms",
        ],
        inplace=True,
        axis=1,
    )
    # package_df["bidirectional_first_seen_ms"] = package_df["bidirectional_first_seen_ms"].astype(str)
    # package_df["bidirectional_last_seen_ms"] = package_df["bidirectional_last_seen_ms"].astype(str)
    # package_df["src2dst_first_seen_ms"] = package_df["src2dst_first_seen_ms"].astype(str)
    # package_df["src2dst_last_seen_ms"] = package_df["src2dst_last_seen_ms"].astype(str)
    # package_df["dst2src_first_seen_ms"] = package_df["dst2src_first_seen_ms"].astype(str)
    # package_df["dst2src_last_seen_ms"] = package_df["dst2src_last_seen_ms"].astype(str)
    # package_df["dst2src_duration_ms"] = package_df["dst2src_duration_ms"].astype(str)
    # package_df["src2dst_duration_ms"] = package_df["src2dst_duration_ms"].astype(str)
    # package_df["bidirectional_duration_ms"] = package_df["bidirectional_duration_ms"].astype(str)

    inserted_num = package_df.to_sql("packages", con=engine, if_exists="append")
    logger.info(f"amount inserted rows {inserted_num}")
    packets_per_sec = inserted_num / NDPI_TIME
    request_bytes_per_sec = package_df["src2dst_bytes"].sum() / NDPI_TIME
    response_bytes_per_sec = package_df["dst2src_bytes"].sum() / NDPI_TIME

    for metric, value in {
        "packets_per_sec": packets_per_sec,
        "request_bytes_per_sec": request_bytes_per_sec,
        "response_bytes_per_sec": response_bytes_per_sec,
    }.items():
        pandas.DataFrame(
            data={"metric": [value]}
        ).to_sql(metric, con=engine, if_exists="append")


if __name__ == "__main__":
    main()
