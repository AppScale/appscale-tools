from tabulate import tabulate
from appscale_logger import AppScaleLogger
from termcolor import colored


def print_table(table_name, headers, data):
  """
  Prints a list of specified data with headers and table name.

  Args:
    table_name: A string representing a name of table.
    headers: A list of statistic headers.
    data: A list of statistics.
  """
  table = tabulate(tabular_data=data, headers=headers, tablefmt='simple',
                   floatfmt=".1f", numalign="right", stralign="left")

  table_width = len(table.split("\n", 2)[1])
  left_signs = "=" * ((table_width - len(table_name) - 2) / 2)
  right_signs = left_signs + (
    "=" if (table_width - len(table_name)) % 2 == 1 else ""
  )
  result_table_name = (
    "{l_signs} {name} {r_signs}"
      .format(l_signs=left_signs, name=table_name, r_signs=right_signs)
  )

  AppScaleLogger.log(colored(text=result_table_name, color="green"))
  AppScaleLogger.log(table + "\n")
