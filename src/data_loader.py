import os
import pandas as pd

class DataLoader:
    """
    Ingests raw network telemetry CSV datasets with support for single files,
    multi-file days, and representative dataset sampling across full time windows.
    """
    def __init__(self, config: dict):
        self.config = config

    def _read_csv_safe(self, file_path: str) -> pd.DataFrame:
        """Reads CSV files handling UTF-8, Latin-1, and corrupted byte encodings robustly."""
        for enc in ["utf-8", "latin1", "cp1252", "iso-8859-1"]:
            try:
                return pd.read_csv(file_path, encoding=enc, encoding_errors="replace", low_memory=False)
            except UnicodeDecodeError:
                continue
            except Exception as e:
                # If engine error, fallback to python engine
                return pd.read_csv(file_path, encoding="latin1", engine="python", encoding_errors="replace")
        return pd.read_csv(file_path, encoding="latin1", encoding_errors="replace", low_memory=False)

    def fetch_dataset(self) -> pd.DataFrame:
        ds_cfg = self.config.get('dataset', {})
        raw_dir = ds_cfg.get('raw_dir', 'data/raw')
        sample_size = ds_cfg.get('sample_size')

        if 'active_day' in ds_cfg and 'files' in ds_cfg:
            active_key = ds_cfg['active_day']
            target = ds_cfg['files'].get(active_key)

            if not target:
                raise KeyError(f"Selected active_day '{active_key}' not found in dataset.files config!")

            print(f"[+] Active Selection: [{active_key}]")

            # Case A: target is a list of multiple CSV files for a single day
            if isinstance(target, list):
                dfs = []
                per_file_sample = (sample_size // len(target)) if sample_size else None

                for fname in target:
                    file_path = os.path.join(raw_dir, fname)
                    if not os.path.exists(file_path):
                        raise FileNotFoundError(f"Dataset file not found: {file_path}")

                    df_full = self._read_csv_safe(file_path)
                    if per_file_sample and len(df_full) > per_file_sample:
                        df_part = df_full.sample(n=per_file_sample, random_state=42)
                    else:
                        df_part = df_full

                    dfs.append(df_part)
                    print(f"  [->] Merged file: {fname} ({len(df_part)} rows sampled)")

                df = pd.concat(dfs, ignore_index=True)
                print(f"[+] Successfully concatenated {len(target)} files into {len(df)} total rows.")

            # Case B: target is a single CSV filename
            else:
                file_path = os.path.join(raw_dir, target)
                if not os.path.exists(file_path):
                    raise FileNotFoundError(f"Dataset file not found: {file_path}")

                df_full = self._read_csv_safe(file_path)
                if sample_size and len(df_full) > sample_size:
                    df = df_full.sample(n=sample_size, random_state=42).reset_index(drop=True)
                    print(f"[+] Sampled {len(df)} representative rows randomly across full dataset.")
                else:
                    df = df_full
                    print(f"[+] Loaded dataset file: {target} ({len(df)} rows)")

        else:
            raw_path = ds_cfg.get('raw_path', 'data/raw/network_logs.csv')
            if not os.path.exists(raw_path):
                raise FileNotFoundError(f"Dataset file not found at: {raw_path}")
            
            df_full = self._read_csv_safe(raw_path)
            if sample_size and len(df_full) > sample_size:
                df = df_full.sample(n=sample_size, random_state=42).reset_index(drop=True)
            else:
                df = df_full

        # Clean column names (strip trailing whitespace common in CIC-IDS2017)
        df.columns = df.columns.str.strip()
        return df