/**
 * storage.js
 */

const STORAGE_KEYS = {

  HISTORY:
    "scan_history",

  SETTINGS:
    "scanner_settings"

};


async function saveScanToHistory(
  scanResult
) {

  const data =
    await chrome.storage.local.get(
      STORAGE_KEYS.HISTORY
    );


  const existing =
    data[
      STORAGE_KEYS.HISTORY
    ];


  const history =
    Array.isArray(existing)
      ? existing
      : [];


  history.unshift(
    scanResult
  );


  const trimmed =
    history.slice(
      0,
      100
    );


  await chrome.storage.local.set({

    [STORAGE_KEYS.HISTORY]:
      trimmed

  });


  return trimmed;
}


async function getScanHistory() {

  const data =
    await chrome.storage.local.get(
      STORAGE_KEYS.HISTORY
    );


  return Array.isArray(
    data[
      STORAGE_KEYS.HISTORY
    ]
  )
    ? data[
        STORAGE_KEYS.HISTORY
      ]
    : [];
}


async function clearScanHistory() {

  await chrome.storage.local.remove(
    STORAGE_KEYS.HISTORY
  );
}


async function getSettings() {

  const defaults = {

    backendUrl:
      "http://127.0.0.1:5000",

    allowActiveScan:
      false,

    theme:
      "dark"

  };


  const data =
    await chrome.storage.local.get(
      STORAGE_KEYS.SETTINGS
    );


  const settings = {

    ...defaults,

    ...(
      data[
        STORAGE_KEYS.SETTINGS
      ] || {}
    )

  };


  settings.backendUrl =
    String(
      settings.backendUrl
    )
      .trim()
      .replace(
        /\/+$/,
        ""
      );


  return settings;
}


async function updateSettings(
  partial
) {

  const current =
    await getSettings();


  const updated = {

    ...current,

    ...partial

  };


  if (
    updated.backendUrl
  ) {

    updated.backendUrl =
      String(
        updated.backendUrl
      )
        .trim()
        .replace(
          /\/+$/,
          ""
        );
  }


  await chrome.storage.local.set({

    [STORAGE_KEYS.SETTINGS]:
      updated

  });


  return updated;
}