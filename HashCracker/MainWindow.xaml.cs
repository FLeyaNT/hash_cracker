using System;
using System.Windows;
using System.Linq;
using System.Windows.Input;
using System.ComponentModel;
using HashCracker.Models;
using HashCracker.Services;

namespace HashCracker
{
    public partial class MainWindow : Window
    {
        private BruteForcer? _forcer;
        private sealed record AlphabetPreset(string Label, string? Characters);
        private string _customAlphabet = "";
        private bool _isCustomAlphabet;
        private bool _closeRequested;

        public MainWindow()
        {
            InitializeComponent();
            int processorCount = Environment.ProcessorCount;
            ThreadsBox.ItemsSource = Enumerable.Range(1, processorCount);
            ThreadsBox.SelectedItem = Math.Min(4, processorCount);
            ProcessorInfoText.Text = $"Логических процессоров: {processorCount}";

            const string lower = "abcdefghijklmnopqrstuvwxyz";
            const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string digits = "0123456789";
            string special = new string(Enumerable.Range(33, 94).Select(c => (char)c)
                .Where(c => !char.IsAsciiLetterOrDigit(c)).ToArray());
            AlphabetPresetBox.ItemsSource = new[]
            {
                new AlphabetPreset("a-z", lower),
                new AlphabetPreset("A-Z", upper),
                new AlphabetPreset("0-9", digits),
                new AlphabetPreset("a-z, A-Z", lower + upper),
                new AlphabetPreset("a-z, 0-9", lower + digits),
                new AlphabetPreset("A-Z, 0-9", upper + digits),
                new AlphabetPreset("a-z, A-Z, 0-9", lower + upper + digits),
                new AlphabetPreset("Спецсимволы (ASCII, без пробела)", special),
                new AlphabetPreset("a-z, A-Z, 0-9 + спецсимволы (без пробела)", lower + upper + digits + special),
                new AlphabetPreset("Свой алфавит", null)
            };
            AlphabetPresetBox.SelectedIndex = 4;
        }

        private void AlphabetPresetBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (AlphabetPresetBox.SelectedItem is not AlphabetPreset preset) return;

            if (_isCustomAlphabet) _customAlphabet = AlphabetBox.Text;
            _isCustomAlphabet = preset.Characters is null;
            AlphabetBox.IsReadOnly = !_isCustomAlphabet;
            AlphabetBox.Text = preset.Characters ?? _customAlphabet;
            if (_isCustomAlphabet) AlphabetBox.Focus();
        }

        private static bool ContainsOnlyDigits(string text) =>
            text.All(c => c >= '0' && c <= '9');

        private void LengthBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            e.Handled = !ContainsOnlyDigits(e.Text);
        }

        private void LengthBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Space) e.Handled = true;
        }

        private void LengthBox_Pasting(object sender, DataObjectPastingEventArgs e)
        {
            if (!e.DataObject.GetDataPresent(DataFormats.UnicodeText) ||
                e.DataObject.GetData(DataFormats.UnicodeText) is not string text ||
                !ContainsOnlyDigits(text))
            {
                e.CancelCommand();
            }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            string hash = HashBox.Text.Trim();
            if (string.IsNullOrEmpty(hash))
            {
                MessageBox.Show(this, "Введите хэш для подбора пароля.", "Проверка параметров",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                HashBox.Focus();
                return;
            }

            string alphabet = AlphabetBox.Text;
            if (string.IsNullOrEmpty(alphabet))
            {
                MessageBox.Show(this, "Введите хотя бы один символ алфавита.", "Проверка параметров",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                AlphabetBox.Focus();
                return;
            }

            if (!int.TryParse(MinLenBox.Text, out int minLen) || minLen < 1 ||
                !int.TryParse(MaxLenBox.Text, out int maxLen) || maxLen < 1)
            {
                MessageBox.Show(this, $"Укажите длины пароля целыми числами от 1 до {BruteForcer.MaxPasswordLength}.",
                    "Проверка параметров", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (minLen > maxLen)
            {
                MessageBox.Show(this, "Минимальная длина не должна превышать максимальную.",
                    "Проверка параметров", MessageBoxButton.OK, MessageBoxImage.Warning);
                MinLenBox.Focus();
                return;
            }

            if (ThreadsBox.SelectedItem is not int threads ||
                threads < 1 || threads > Environment.ProcessorCount)
            {
                MessageBox.Show(this, "Выберите количество потоков из списка.", "Проверка параметров",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                ThreadsBox.Focus();
                return;
            }

            var algoText = (AlgorithmBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content.ToString();
            HashAlgorithmType type = algoText switch
            {
                "MD5" => HashAlgorithmType.MD5,
                "SHA-1" => HashAlgorithmType.SHA1,
                "bcrypt" => HashAlgorithmType.BCrypt,
                "Argon2id" => HashAlgorithmType.Argon2,
                _ => HashAlgorithmType.MD5
            };

            string originalAlphabet = alphabet;
            try
            {
                alphabet = BruteForcer.NormalizeAlphabet(alphabet);
                BruteForcer.ValidateParameters(type, hash, alphabet, minLen, maxLen, threads);
            }
            catch (ArgumentException ex)
            {
                MessageBox.Show(this, ex.Message, "Проверка параметров", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            AlphabetBox.Text = alphabet;
            if (_isCustomAlphabet) _customAlphabet = alphabet;
            var startedAt = DateTimeOffset.Now;
            LogBox.AppendText($"\n--- {startedAt:yyyy-MM-dd HH:mm:ss zzz}: {algoText} ---\n");
            LogBox.AppendText($"Длина: {minLen}–{maxLen}; потоков выбрано: {threads}; символов алфавита: {alphabet.EnumerateRunes().Count()}.\n");
            if (originalAlphabet != alphabet) LogBox.AppendText("Повторяющиеся символы алфавита удалены.\n");
            StatusText.Text = "Выполняется перебор...";
            ProgressIndicator.IsIndeterminate = true;
            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;

            _forcer = new BruteForcer();

            try
            {
                var result = await _forcer.RunAsync(type, hash, alphabet, minLen, maxLen, threads,
                    msg => Dispatcher.Invoke(() => LogBox.AppendText(msg + "\n")));

                if (result.Found)
                {
                    LogBox.AppendText($"\nПароль найден: {result.Password}\n");
                }
                else if (result.Status == CrackStatus.Cancelled)
                {
                    LogBox.AppendText("\nПеребор остановлен пользователем. Не все варианты проверены.\n");
                }
                else
                {
                    LogBox.AppendText("\nПароль не найден в заданном диапазоне.\n");
                }

                LogBox.AppendText($"Время: {result.ElapsedSeconds:F3} сек.\n");
                LogBox.AppendText($"Попыток: {result.AttemptsCount}\n");
                LogBox.AppendText($"Комбинаций в диапазоне: {result.TotalCombinations}; поисковых задач: {result.WorkerCount}.\n");

                StatusText.Text = result.Status switch
                {
                    CrackStatus.Found => "Найдено",
                    CrackStatus.Cancelled => "Остановлено пользователем",
                    _ => "Не найдено: диапазон проверен"
                };

            }
            catch (Exception ex)
            {
                LogBox.AppendText($"Ошибка: {ex.Message}\n");
                StatusText.Text = "Ошибка";
            }
            finally
            {
                ProgressIndicator.IsIndeterminate = false;
                StartButton.IsEnabled = true;
                StopButton.IsEnabled = false;
                _forcer = null;
                LogBox.ScrollToEnd();
                if (_closeRequested) Close();
            }
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            _forcer?.Cancel();
            StopButton.IsEnabled = false;
            StatusText.Text = "Остановка: ожидается завершение текущих проверок...";
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            base.OnClosing(e);
            if (_forcer is null) return;
            e.Cancel = true;
            _closeRequested = true;
            _forcer?.Cancel();
            StopButton.IsEnabled = false;
            StatusText.Text = "Остановка перед закрытием...";
        }
    }
}
