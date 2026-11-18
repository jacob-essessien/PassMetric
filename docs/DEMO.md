# PassMetric demonstration

[MP4 walkthrough](media/walkthrough.mp4) · [Animated preview](media/walkthrough.gif)

Recorded from the running application on **18 November 2026**, using the application
code from commit `35577ee`. The **38-second continuous dashboard recording** preserves
the real interactions and their timing: typing, filtering, opening a form, saving
a note, adjusting generator controls and navigating between features. There are
no scene cuts, added captions or footer.

The browser viewport was captured continuously (618 frames over 38.22 seconds)
and encoded at 1280 × 720, 20 fps, with timestamps preserved. The GIF is a smaller
960 × 540, 12 fps preview of the same recording.

## Journey

| Time | Interaction |
| --- | --- |
| 00:00–00:03 | Start on the overview of the unlocked synthetic vault. |
| 00:03–00:15 | Search for Reading Room, open its edit form, type and save a fictional note, then clear the search. |
| 00:15–00:24 | Increase the password length from 16 to 24, toggle symbols, generate a password and regenerate it. |
| 00:24–00:31 | Type `password123` into Analyzer and inspect the returned 19/100 score, warnings and recommendations. |
| 00:31–00:35 | Open Health Audit: six entries, four weak passwords and a mean backend score of 45.4. |
| 00:35–00:38 | Return to the overview. |

A separate [vault screenshot](media/03-vault.jpg), captured on 17 November,
is also available.

All addresses use `example.com`; entries and passwords are fictional. No SMTP
messages were sent. A local seed script created the account as verified, so this
recording starts after sign-in and does not demonstrate registration or email delivery. CSRF protection,
authentication, encryption and the application's routes remained enabled.

No RockYou corpus, EFF wordlist or trained pickle model was supplied. The existing
NLTK words corpus was available on the capture machine. The media therefore
demonstrate the rules path, not ML accuracy or breach coverage.

## Reproduce the workflow

Follow the README's local setup in an isolated checkout. Create and verify a
test account using your own local configuration; use fictional details. Add some
dummy credentials, search for one in Vault and edit its notes. Open Generator,
adjust the length and character options, then generate and regenerate a password.
Open Analyzer and try `password123`, then inspect Health Audit and return to
Overview. Never use demonstration passwords for real accounts.

The capture used Python 3.12.14 and the pinned PassMetric requirements. The app ran
on loopback port 8801. The temporary seed/launch scripts and database are excluded
from the publication package; they are not new application features.

## Verification and known discrepancies

The live capture completed without browser-action errors. The server returned
successful responses for saving the note, generating passwords and analysing
them. The full MP4 decoded successfully, and sampled frames confirmed the typing,
form, slider changes, analysis result and audit. No application source was changed
for this recording; the earlier test results below still apply.

The existing unit/integration suites were run in a separate disposable checkout
with an explicit writable pytest temporary directory: **129 passed, 2 failed,
1 skipped**. The skip requires the optional RockYou dataset. The two failures
are `test_strong_password_scores_high` and `test_analyze_strong_password`; both
expect at least 60 for the same fixture, while the evaluator returns 55 here.
No test assertions or evaluator code were changed for this presentation task.

```sh
python -m pytest backend/tests/unit backend/tests/integration -q --basetemp ./pytest-demo-temp
```

Use that command only in the disposable checkout described by the README: the
integration fixture recreates tables. An initial sandbox run had 12 temporary
directory permission errors; those disappeared with an explicit writable path.

The vault displays a lightweight browser score of 50 for `password123`, whereas
the full analyser/audit returns 19. The overview similarly counts one weak
password in this fixture while the backend audit counts four. These are existing
differences between evaluation paths, not evidence of equivalent scoring. Unifying
those paths and resolving the two test expectations is a useful next maintenance
checkpoint.
